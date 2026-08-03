package s3

import (
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

	r := httptest.NewRequest(http.MethodPut, "http://minio:9000/uploads/payload.sh", strings.NewReader("#!/bin/sh\nid\n"))
	r.RemoteAddr = "203.0.113.8:44221"
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIABOT/20260803/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc")
	w := httptest.NewRecorder()
	newHandler().ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code)
	require.NotEmpty(t, w.Header().Get("ETag"))

	select {
	case got := <-requestCh:
		require.Equal(t, "203.0.113.8", got.RemoteAddr)
		require.Equal(t, "uploads", got.Bucket)
		require.Equal(t, "payload.sh", got.Key)
		require.Equal(t, "AKIABOT", got.AccessKeyId)
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
