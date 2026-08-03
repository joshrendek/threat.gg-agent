package s3

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joshrendek/threat.gg-agent/cmdresp"
	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
)

const (
	defaultPort       = "9000"
	maxUploadBytes    = 64 << 20
	maxPreviewBytes   = 4 << 10
	maxConcurrent     = 4
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 30 * time.Second
)

var logger = zerolog.New(os.Stdout).With().Caller().Str("honeypot", "s3").Logger()
var saveS3Request = persistence.SaveS3Request
var saveFile = persistence.SaveFile
var requestSlots = make(chan struct{}, maxConcurrent)
var fileSaveSlots = make(chan struct{}, maxConcurrent)

type honeypot struct{ logger zerolog.Logger }

func New() honeypots.Honeypot {
	return &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "s3").Logger()}
}

func (h *honeypot) Name() string { return "s3" }

func (h *honeypot) Start() {
	port := os.Getenv("S3_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}
	server := &http.Server{
		Addr:              ":" + port,
		Handler:           cmdresp.MuxMiddleware("s3")(newHandler()),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    64 << 10,
	}
	h.logger.Info().Str("port", port).Msg("starting MinIO/S3 honeypot")
	h.logger.Fatal().Err(server.ListenAndServe()).Msg("failed to start MinIO/S3 honeypot")
}

func newHandler() http.Handler { return http.HandlerFunc(serveHTTP) }

type captureMetadata struct {
	Operation         string              `json:"operation"`
	Headers           map[string]string   `json:"headers"`
	Query             map[string][]string `json:"query"`
	ContentLength     int64               `json:"content_length"`
	BodyPreviewBase64 string              `json:"body_preview_base64,omitempty"`
	Presigned         bool                `json:"presigned"`
	SignedHeaders     string              `json:"signed_headers,omitempty"`
}

func serveHTTP(w http.ResponseWriter, r *http.Request) {
	guid := uuid.NewV4().String()
	requestID := strings.ReplaceAll(guid, "-", "")[:16]
	w.Header().Set("Server", "MinIO")
	w.Header().Set("x-amz-request-id", requestID)
	w.Header().Set("x-amz-id-2", requestID+"MINIO")
	w.Header().Set("x-amz-bucket-region", "us-east-1")
	select {
	case requestSlots <- struct{}{}:
		defer func() { <-requestSlots }()
	default:
		writeError(w, http.StatusServiceUnavailable, "SlowDown", "Please reduce your request rate.", r.URL.Path, requestID)
		return
	}

	if handleMinIOProbe(w, r) {
		persist(r, guid, "MinIOProbe", "", "", nil, false)
		return
	}

	bucket, key := resourceFromRequest(r)
	operation := operationFor(r, bucket, key)
	body, tooLarge, err := readBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "InvalidRequest", "Could not read request body", r.URL.Path, requestID)
		persist(r, guid, operation, bucket, key, nil, false)
		return
	}
	if tooLarge {
		writeError(w, http.StatusRequestEntityTooLarge, "EntityTooLarge", "Your proposed upload exceeds the maximum allowed object size.", r.URL.Path, requestID)
		persist(r, guid, operation, bucket, key, body, true)
		return
	}
	persist(r, guid, operation, bucket, key, body, false)

	switch operation {
	case "ListBuckets":
		writeXML(w, http.StatusOK, listBuckets())
	case "ListObjects":
		data, ok := listObjects(bucket, r.URL.Query().Get("prefix"))
		if !ok {
			writeError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist", r.URL.Path, requestID)
			return
		}
		writeXML(w, http.StatusOK, data)
	case "GetBucketAcl":
		if _, ok := fakeObjects[bucket]; !ok {
			writeError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist", r.URL.Path, requestID)
			return
		}
		writeXML(w, http.StatusOK, []byte(xmlACL))
	case "HeadBucket":
		if _, ok := fakeObjects[bucket]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	case "GetObject", "HeadObject":
		serveObject(w, r, bucket, key, operation == "HeadObject", requestID)
	case "PutObject":
		if _, ok := fakeObjects[bucket]; !ok {
			writeError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist", r.URL.Path, requestID)
			return
		}
		w.Header().Set("ETag", "\""+etag(body)+"\"")
		w.WriteHeader(http.StatusOK)
	case "CreateMultipartUpload":
		writeXML(w, http.StatusOK, []byte(fmt.Sprintf(xmlInitiateMultipart, xmlText(bucket), xmlText(key), requestID)))
	case "UploadPart":
		w.Header().Set("ETag", "\""+etag(body)+"-1\"")
		w.WriteHeader(http.StatusOK)
	case "CompleteMultipartUpload":
		writeXML(w, http.StatusOK, []byte(fmt.Sprintf(xmlCompleteMultipart, xmlText(bucket), xmlText(key), xmlText(bucket), xmlText(key), etag(body))))
	case "DeleteObject", "DeleteObjects":
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusNotImplemented, "NotImplemented", "A header you provided implies functionality that is not implemented", r.URL.Path, requestID)
	}
}

func readBody(r *http.Request) ([]byte, bool, error) {
	if r.Body == nil || r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodDelete {
		return nil, false, nil
	}
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, maxUploadBytes+1))
	if err != nil {
		return nil, false, err
	}
	if len(b) > maxUploadBytes {
		return b[:maxUploadBytes], true, nil
	}
	return b, false, nil
}

func persist(r *http.Request, guid, operation, bucket, key string, body []byte, truncated bool) {
	accessKey, region, signedHeaders, presigned := parseAuth(r)
	preview := body
	if len(preview) > maxPreviewBytes {
		preview = preview[:maxPreviewBytes]
	}
	meta := captureMetadata{
		Operation: operation, Headers: persistence.HttpToMap(map[string][]string(r.Header)),
		Query: r.URL.Query(), ContentLength: r.ContentLength, Presigned: presigned,
		SignedHeaders: signedHeaders,
	}
	if len(preview) > 0 {
		meta.BodyPreviewBase64 = base64.StdEncoding.EncodeToString(preview)
	}
	if truncated {
		meta.Headers["X-ThreatGG-Capture-Truncated"] = "true"
	}
	data, _ := json.Marshal(meta)
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	req := &proto.S3Request{
		RemoteAddr: host, Guid: guid, Method: r.Method, Path: r.URL.EscapedPath(),
		Bucket: bucket, Key: key, AccessKeyId: accessKey, Region: region,
		UserAgent: r.UserAgent(), Data: string(data),
	}
	go func() {
		if err := saveS3Request(req); err != nil {
			logger.Error().Err(err).Msg("error saving S3 request")
		}
	}()
	if operation == "PutObject" && len(body) > 0 && !truncated {
		filename := key
		if filename == "" {
			filename = "object.bin"
		}
		select {
		case fileSaveSlots <- struct{}{}:
			go func(data []byte) {
				defer func() { <-fileSaveSlots }()
				if err := saveFile(data, filename, guid, "s3"); err != nil {
					logger.Error().Err(err).Msg("error saving S3 object")
				}
			}(body)
		default:
			logger.Warn().Msg("dropping S3 object from file pipeline because persistence is saturated")
		}
	}
}

func parseAuth(r *http.Request) (accessKey, region, signedHeaders string, presigned bool) {
	credential := ""
	auth := r.Header.Get("Authorization")
	if i := strings.Index(auth, "Credential="); i >= 0 {
		credential = auth[i+len("Credential="):]
		if comma := strings.IndexByte(credential, ','); comma >= 0 {
			credential = credential[:comma]
		}
	}
	if i := strings.Index(auth, "SignedHeaders="); i >= 0 {
		signedHeaders = auth[i+len("SignedHeaders="):]
		if comma := strings.IndexByte(signedHeaders, ','); comma >= 0 {
			signedHeaders = signedHeaders[:comma]
		}
	}
	if credential == "" {
		credential = r.URL.Query().Get("X-Amz-Credential")
		if credential != "" {
			presigned = true
			signedHeaders = r.URL.Query().Get("X-Amz-SignedHeaders")
		}
	}
	credential, _ = url.QueryUnescape(strings.TrimSpace(credential))
	parts := strings.Split(credential, "/")
	if len(parts) >= 4 {
		return parts[0], parts[2], signedHeaders, presigned
	}
	return credential, "", signedHeaders, presigned
}

func resourceFromRequest(r *http.Request) (string, string) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if net.ParseIP(host) == nil && host != "localhost" {
		label := strings.Split(host, ".")[0]
		if _, ok := fakeObjects[label]; ok {
			return label, strings.TrimPrefix(r.URL.Path, "/")
		}
	}
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		return "", ""
	}
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], parts[1]
}

func operationFor(r *http.Request, bucket, key string) string {
	q := r.URL.Query()
	switch {
	case r.Method == http.MethodGet && bucket == "":
		return "ListBuckets"
	case r.Method == http.MethodGet && key == "" && q.Has("acl"):
		return "GetBucketAcl"
	case r.Method == http.MethodGet && key == "":
		return "ListObjects"
	case r.Method == http.MethodHead && key == "":
		return "HeadBucket"
	case r.Method == http.MethodGet:
		return "GetObject"
	case r.Method == http.MethodHead:
		return "HeadObject"
	case r.Method == http.MethodPost && q.Has("uploads"):
		return "CreateMultipartUpload"
	case r.Method == http.MethodPut && q.Get("uploadId") != "":
		return "UploadPart"
	case r.Method == http.MethodPost && q.Get("uploadId") != "":
		return "CompleteMultipartUpload"
	case r.Method == http.MethodPut:
		return "PutObject"
	case r.Method == http.MethodPost && q.Has("delete"):
		return "DeleteObjects"
	case r.Method == http.MethodDelete:
		return "DeleteObject"
	default:
		return "Unknown"
	}
}

func serveObject(w http.ResponseWriter, r *http.Request, bucket, key string, head bool, requestID string) {
	objects, ok := fakeObjects[bucket]
	if !ok {
		writeError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist", r.URL.Path, requestID)
		return
	}
	o, ok := objects[key]
	if !ok {
		writeError(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist", r.URL.Path, requestID)
		return
	}
	body := o.Body
	status := http.StatusOK
	start, end, ranged := parseRange(r.Header.Get("Range"), len(body))
	if ranged {
		status = http.StatusPartialContent
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(body)))
		body = body[start : end+1]
	}
	w.Header().Set("Content-Type", o.ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("ETag", "\""+etag(o.Body)+"\"")
	w.Header().Set("Last-Modified", o.LastModified.Format(http.TimeFormat))
	w.WriteHeader(status)
	if !head {
		_, _ = w.Write(body)
	}
}

func parseRange(header string, size int) (start, end int, ok bool) {
	if !strings.HasPrefix(header, "bytes=") || strings.Contains(header, ",") || size == 0 {
		return 0, 0, false
	}
	parts := strings.SplitN(strings.TrimPrefix(header, "bytes="), "-", 2)
	if len(parts) != 2 || parts[0] == "" {
		return 0, 0, false
	}
	start, err := strconv.Atoi(parts[0])
	if err != nil || start < 0 || start >= size {
		return 0, 0, false
	}
	end = size - 1
	if parts[1] != "" {
		if parsed, err := strconv.Atoi(parts[1]); err == nil && parsed >= start && parsed < size {
			end = parsed
		}
	}
	return start, end, true
}

func handleMinIOProbe(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/minio/health/live", "/minio/health/ready", "/minio/health/cluster":
		w.WriteHeader(http.StatusOK)
		return true
	case "/minio/bootstrap/v1/verify":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"MinioEnv":{"MINIO_ROOT_USER":"minioadmin","MINIO_REGION_NAME":"us-east-1"}}`))
		return true
	default:
		return false
	}
}

func writeXML(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeError(w http.ResponseWriter, status int, code, message, resource, requestID string) {
	writeXML(w, status, s3Error(code, message, resource, requestID))
}

const xmlACL = `<?xml version="1.0" encoding="UTF-8"?><AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>minio</ID><DisplayName>minio</DisplayName></Owner><AccessControlList><Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID>minio</ID><DisplayName>minio</DisplayName></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>`
const xmlInitiateMultipart = `<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>%s</Bucket><Key>%s</Key><UploadId>%s</UploadId></InitiateMultipartUploadResult>`
const xmlCompleteMultipart = `<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Location>http://minio:9000/%s/%s</Location><Bucket>%s</Bucket><Key>%s</Key><ETag>"%s-1"</ETag></CompleteMultipartUploadResult>`
