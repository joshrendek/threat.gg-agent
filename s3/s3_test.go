package s3

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/stretchr/testify/require"
)

func TestListBucketsAndObjectsAreValidS3XML(t *testing.T) {
	var buckets listBucketsXML
	require.NoError(t, xml.Unmarshal(listBuckets(), &buckets))
	require.Equal(t, s3Namespace, buckets.Xmlns)
	require.Len(t, buckets.Buckets, 4)
	require.Equal(t, "backups", buckets.Buckets[0].Name)

	body, ok := listObjects("data", "cred")
	require.True(t, ok)
	var objects listObjectsXML
	require.NoError(t, xml.Unmarshal(body, &objects))
	require.Equal(t, "data", objects.Name)
	require.Equal(t, 1, objects.KeyCount)
	require.Equal(t, "credentials.json", objects.Contents[0].Key)
}

func TestParseAuthHeaderAndPresignedQuery(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://minio:9000/backups", nil)
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIATEST/20260803/us-west-2/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc")
	key, region, signed, presigned := parseAuth(r)
	require.Equal(t, "AKIATEST", key)
	require.Equal(t, "us-west-2", region)
	require.Equal(t, "host;x-amz-date", signed)
	require.False(t, presigned)

	r = httptest.NewRequest(http.MethodGet, "http://minio:9000/backups?X-Amz-Credential=AKIAPRE%2F20260803%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-SignedHeaders=host", nil)
	key, region, signed, presigned = parseAuth(r)
	require.Equal(t, "AKIAPRE", key)
	require.Equal(t, "eu-west-1", region)
	require.Equal(t, "host", signed)
	require.True(t, presigned)
}

func TestResourceParsingSupportsPathAndVirtualHostStyles(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9000/data/config.yaml", nil)
	bucket, key := resourceFromRequest(r)
	require.Equal(t, "data", bucket)
	require.Equal(t, "config.yaml", key)

	r = httptest.NewRequest(http.MethodGet, "http://data.minio.example/config.yaml", nil)
	bucket, key = resourceFromRequest(r)
	require.Equal(t, "data", bucket)
	require.Equal(t, "config.yaml", key)

	r = httptest.NewRequest(http.MethodGet, "http://stolen.minio.example/secrets.txt", nil)
	bucket, key = resourceFromRequest(r)
	require.Equal(t, "stolen", bucket)
	require.Equal(t, "secrets.txt", key)
}

func TestHandlerEnumerateRangeAndMissingKey(t *testing.T) {
	oldSave := saveS3Request
	saveS3Request = func(*proto.S3Request) error { return nil }
	t.Cleanup(func() { saveS3Request = oldSave })

	ts := httptest.NewServer(newHandler())
	t.Cleanup(ts.Close)

	res, err := http.Get(ts.URL + "/")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, res.StatusCode)
	data, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	require.Contains(t, string(data), "ListAllMyBucketsResult")
	require.Equal(t, "MinIO", res.Header.Get("Server"))

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/data/config.yaml", nil)
	req.Header.Set("Range", "bytes=0-10")
	res, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusPartialContent, res.StatusCode)
	require.Equal(t, "bytes 0-10/77", res.Header.Get("Content-Range"))
	_ = res.Body.Close()

	res, err = http.Get(ts.URL + "/data/missing")
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, res.StatusCode)
	data, _ = io.ReadAll(res.Body)
	_ = res.Body.Close()
	require.Contains(t, string(data), "NoSuchKey")
}

func TestPutObjectPersistsTelemetryAndFile(t *testing.T) {
	requestCh := make(chan *proto.S3Request, 1)
	fileCh := make(chan struct {
		data, filename, guid, source string
	}, 1)
	oldRequest, oldFile := saveS3Request, saveFile
	saveS3Request = func(in *proto.S3Request) error { requestCh <- in; return nil }
	saveFile = func(data []byte, filename, guid, source string) error {
		fileCh <- struct{ data, filename, guid, source string }{string(data), filename, guid, source}
		return nil
	}
	t.Cleanup(func() { saveS3Request, saveFile = oldRequest, oldFile })

	r := httptest.NewRequest(http.MethodPut, "http://minio:9000/uploads/tools/../payload.sh?X-Amz-Security-Token=token", strings.NewReader("#!/bin/sh\nid\n"))
	r.RemoteAddr = "203.0.113.8:44221"
	r.Header.Set("User-Agent", "aws-cli/2.31.0")
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIABOT/20260803/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc")
	w := httptest.NewRecorder()
	newHandler().ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code)
	require.NotEmpty(t, w.Header().Get("ETag"))

	select {
	case got := <-requestCh:
		require.Equal(t, "203.0.113.8", got.RemoteAddr)
		require.Equal(t, "uploads", got.Bucket)
		require.Equal(t, "tools/../payload.sh", got.Key)
		require.Equal(t, "AKIABOT", got.AccessKeyId)
		require.Equal(t, "PUT", got.Method)
		require.Equal(t, "/uploads/tools/../payload.sh", got.Path)
		require.Equal(t, "us-east-1", got.Region)
		require.Equal(t, "aws-cli/2.31.0", got.UserAgent)
		var metadata captureMetadata
		require.NoError(t, json.Unmarshal([]byte(got.Data), &metadata))
		require.Equal(t, "PutObject", metadata.Operation)
		require.Equal(t, int64(13), metadata.ContentLength)
		require.Equal(t, "host", metadata.SignedHeaders)
		require.Equal(t, "aws-cli/2.31.0", metadata.Headers["User-Agent"])
		require.Equal(t, []string{"token"}, metadata.Query["X-Amz-Security-Token"])
		preview, err := base64.StdEncoding.DecodeString(metadata.BodyPreviewBase64)
		require.NoError(t, err)
		require.Equal(t, "#!/bin/sh\nid\n", string(preview))
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for S3 telemetry")
	}
	select {
	case got := <-fileCh:
		require.Equal(t, "#!/bin/sh\nid\n", got.data)
		require.Equal(t, "payload.sh", got.filename)
		require.Equal(t, "s3", got.source)
		require.NotEmpty(t, got.guid)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for S3 file persistence")
	}
}

func TestOversizedPutIsRejectedAndNotSentToFilePipeline(t *testing.T) {
	requestCh := make(chan *proto.S3Request, 1)
	fileCh := make(chan struct{}, 1)
	oldRequest, oldFile := saveS3Request, saveFile
	saveS3Request = func(in *proto.S3Request) error { requestCh <- in; return nil }
	saveFile = func([]byte, string, string, string) error { fileCh <- struct{}{}; return nil }
	t.Cleanup(func() { saveS3Request, saveFile = oldRequest, oldFile })

	r := httptest.NewRequest(http.MethodPut, "http://minio:9000/uploads/too-large.bin", strings.NewReader("small"))
	r.ContentLength = maxUploadBytes + 1
	w := httptest.NewRecorder()
	newHandler().ServeHTTP(w, r)
	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	require.Contains(t, w.Body.String(), "EntityTooLarge")

	select {
	case got := <-requestCh:
		var metadata captureMetadata
		require.NoError(t, json.Unmarshal([]byte(got.Data), &metadata))
		require.Equal(t, "true", metadata.Headers["X-ThreatGG-Capture-Truncated"])
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for oversized request telemetry")
	}
	select {
	case <-fileCh:
		t.Fatal("oversized upload reached the file pipeline")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestS3OperationResponses(t *testing.T) {
	oldRequest := saveS3Request
	saveS3Request = func(*proto.S3Request) error { return nil }
	t.Cleanup(func() { saveS3Request = oldRequest })

	tests := []struct {
		name, method, target, body, contains string
		status                               int
	}{
		{"bucket acl", http.MethodGet, "http://minio:9000/data?acl", "", "AccessControlPolicy", http.StatusOK},
		{"head bucket", http.MethodHead, "http://minio:9000/data", "", "", http.StatusOK},
		{"head object", http.MethodHead, "http://minio:9000/data/config.yaml", "", "", http.StatusOK},
		{"start multipart", http.MethodPost, "http://minio:9000/uploads/archive.bin?uploads", "", "InitiateMultipartUploadResult", http.StatusOK},
		{"upload part", http.MethodPut, "http://minio:9000/uploads/archive.bin?partNumber=1&uploadId=abc", "part", "", http.StatusOK},
		{"complete multipart", http.MethodPost, "http://minio:9000/uploads/archive.bin?uploadId=abc", "<CompleteMultipartUpload/>", "CompleteMultipartUploadResult", http.StatusOK},
		{"delete object", http.MethodDelete, "http://minio:9000/uploads/archive.bin", "", "", http.StatusNoContent},
		{"delete objects", http.MethodPost, "http://minio:9000/uploads?delete", "<Delete><Object><Key>a&amp;b</Key></Object></Delete>", "<Key>a&amp;b</Key>", http.StatusOK},
		{"health", http.MethodGet, "http://minio:9000/minio/health/live", "", "", http.StatusOK},
		{"unknown", http.MethodPatch, "http://minio:9000/data/config.yaml", "", "NotImplemented", http.StatusNotImplemented},
		{"missing bucket", http.MethodGet, "http://minio:9000/absent", "", "NoSuchBucket", http.StatusNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
			w := httptest.NewRecorder()
			newHandler().ServeHTTP(w, r)
			require.Equal(t, tc.status, w.Code)
			if tc.contains != "" {
				require.Contains(t, w.Body.String(), tc.contains)
			}
			if tc.name == "upload part" {
				require.Equal(t, "\"f4c9385f1902f7334b00b9b4ecd164de\"", w.Header().Get("ETag"))
			}
		})
	}
}

func TestRangeParsingAndInvalidRangeResponse(t *testing.T) {
	for _, tc := range []struct {
		header     string
		start, end int
		ok         bool
	}{
		{"bytes=0-10", 0, 10, true},
		{"bytes=5-", 5, 76, true},
		{"bytes=-5", 72, 76, true},
		{"bytes=-100", 0, 76, true},
		{"bytes=5-100", 5, 76, true},
		{"bytes=10-5", 0, 0, false},
		{"bytes=100-", 0, 0, false},
		{"bytes=0-1,4-5", 0, 0, false},
		{"items=0-1", 0, 0, false},
	} {
		start, end, ok := parseRange(tc.header, 77)
		require.Equal(t, tc.ok, ok, tc.header)
		require.Equal(t, tc.start, start, tc.header)
		require.Equal(t, tc.end, end, tc.header)
	}

	oldRequest := saveS3Request
	saveS3Request = func(*proto.S3Request) error { return nil }
	t.Cleanup(func() { saveS3Request = oldRequest })
	r := httptest.NewRequest(http.MethodGet, "http://minio:9000/data/config.yaml", nil)
	r.Header.Set("Range", "bytes=99-100")
	w := httptest.NewRecorder()
	newHandler().ServeHTTP(w, r)
	require.Equal(t, http.StatusRequestedRangeNotSatisfiable, w.Code)
	require.Equal(t, "bytes */77", w.Header().Get("Content-Range"))
	require.Contains(t, w.Body.String(), "InvalidRange")
}

func TestTelemetrySaturationDropsWithoutBlocking(t *testing.T) {
	for i := 0; i < maxTelemetrySaves; i++ {
		telemetrySaveSlots <- struct{}{}
	}
	t.Cleanup(func() {
		for i := 0; i < maxTelemetrySaves; i++ {
			<-telemetrySaveSlots
		}
	})

	called := make(chan struct{}, 1)
	oldRequest := saveS3Request
	saveS3Request = func(*proto.S3Request) error { called <- struct{}{}; return nil }
	t.Cleanup(func() { saveS3Request = oldRequest })
	r := httptest.NewRequest(http.MethodGet, "http://minio:9000/", nil)
	w := httptest.NewRecorder()
	newHandler().ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code)
	select {
	case <-called:
		t.Fatal("telemetry persistence ran despite saturation")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestMultipartResponseEscapesAttackerControlledKey(t *testing.T) {
	oldSave := saveS3Request
	saveS3Request = func(*proto.S3Request) error { return nil }
	t.Cleanup(func() { saveS3Request = oldSave })
	r := httptest.NewRequest(http.MethodPost, "http://minio:9000/uploads/a%26b?uploads", nil)
	w := httptest.NewRecorder()
	newHandler().ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code)
	var decoded struct {
		Key string `xml:"Key"`
	}
	require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &decoded))
	require.Equal(t, "a&b", decoded.Key)
}

func TestHandlerReturnsS3SlowDownWhenSaturated(t *testing.T) {
	for i := 0; i < maxConcurrent; i++ {
		requestSlots <- struct{}{}
	}
	t.Cleanup(func() {
		for i := 0; i < maxConcurrent; i++ {
			<-requestSlots
		}
	})

	r := httptest.NewRequest(http.MethodPut, "http://minio:9000/uploads/large.bin", strings.NewReader("payload"))
	w := httptest.NewRecorder()
	newHandler().ServeHTTP(w, r)
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	require.Contains(t, w.Body.String(), "SlowDown")
}

func TestAWSCLICompatibility(t *testing.T) {
	aws, err := exec.LookPath("aws")
	if err != nil {
		t.Skip("AWS CLI is not installed")
	}

	oldSave := saveS3Request
	saveS3Request = func(*proto.S3Request) error { return nil }
	t.Cleanup(func() { saveS3Request = oldSave })

	ts := httptest.NewServer(newHandler())
	t.Cleanup(ts.Close)

	env := append(os.Environ(),
		"AWS_ACCESS_KEY_ID=AKIAREFERENCECLIENT",
		"AWS_SECRET_ACCESS_KEY=reference-client-secret",
		"AWS_DEFAULT_REGION=us-east-1",
		"AWS_EC2_METADATA_DISABLED=true",
		"AWS_PAGER=",
	)
	run := func(args ...string) []byte {
		t.Helper()
		base := []string{"--endpoint-url", ts.URL, "--no-cli-pager", "s3api"}
		cmd := exec.Command(aws, append(base, args...)...)
		cmd.Env = env
		out, runErr := cmd.CombinedOutput()
		require.NoError(t, runErr, "aws %s failed: %s", strings.Join(args, " "), out)
		return out
	}

	require.Contains(t, string(run("list-buckets")), `"Name": "backups"`)
	require.Contains(t, string(run("list-objects-v2", "--bucket", "data")), `"Key": "credentials.json"`)

	destination := filepath.Join(t.TempDir(), "config.yaml")
	run("get-object", "--bucket", "data", "--key", "config.yaml", destination)
	downloaded, err := os.ReadFile(destination)
	require.NoError(t, err)
	require.Contains(t, string(downloaded), "production")
}
