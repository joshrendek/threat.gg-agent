package s3

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"sort"
	"time"
)

const s3Namespace = "http://s3.amazonaws.com/doc/2006-03-01/"

type fakeObject struct {
	Key          string
	Body         []byte
	ContentType  string
	LastModified time.Time
}

var creationTime = time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC)

var fakeObjects = map[string]map[string]fakeObject{
	"backups": {
		"database-2026-07-31.sql.gz": {Key: "database-2026-07-31.sql.gz", Body: []byte("placeholder backup archive\n"), ContentType: "application/gzip", LastModified: creationTime},
		"users-export.csv":           {Key: "users-export.csv", Body: []byte("id,email,role\n1,admin@example.internal,admin\n"), ContentType: "text/csv", LastModified: creationTime},
	},
	"data": {
		"credentials.json": {Key: "credentials.json", Body: []byte("{\"aws_access_key_id\":\"AKIAIOSFODNN7EXAMPLE\",\"aws_secret_access_key\":\"EXAMPLEKEYNOTVALID000000000000000000\"}\n"), ContentType: "application/json", LastModified: creationTime},
		"config.yaml":      {Key: "config.yaml", Body: []byte("environment: production\ndatabase_url: postgres://app:example@db.internal/app\n"), ContentType: "application/yaml", LastModified: creationTime},
	},
	"logs": {
		"access-2026-07.log": {Key: "access-2026-07.log", Body: []byte("2026-07-31T23:59:58Z GET /health 200\n"), ContentType: "text/plain", LastModified: creationTime},
	},
	"uploads": {},
}

func etag(body []byte) string {
	sum := md5.Sum(body) // S3's single-part ETag is conventionally the content MD5.
	return hex.EncodeToString(sum[:])
}

type ownerXML struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

type bucketXML struct {
	Name         string `xml:"Name"`
	CreationDate string `xml:"CreationDate"`
}

type listBucketsXML struct {
	XMLName xml.Name    `xml:"ListAllMyBucketsResult"`
	Xmlns   string      `xml:"xmlns,attr"`
	Owner   ownerXML    `xml:"Owner"`
	Buckets []bucketXML `xml:"Buckets>Bucket"`
}

type objectXML struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int    `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
}

type listObjectsXML struct {
	XMLName     xml.Name    `xml:"ListBucketResult"`
	Xmlns       string      `xml:"xmlns,attr"`
	Name        string      `xml:"Name"`
	Prefix      string      `xml:"Prefix"`
	KeyCount    int         `xml:"KeyCount"`
	MaxKeys     int         `xml:"MaxKeys"`
	IsTruncated bool        `xml:"IsTruncated"`
	Contents    []objectXML `xml:"Contents"`
}

type deleteObjectsRequestXML struct {
	Objects []struct {
		Key string `xml:"Key"`
	} `xml:"Object"`
}

type deleteObjectsResultXML struct {
	XMLName xml.Name `xml:"DeleteResult"`
	Xmlns   string   `xml:"xmlns,attr"`
	Deleted []struct {
		Key string `xml:"Key"`
	} `xml:"Deleted"`
}

type errorXML struct {
	XMLName  xml.Name `xml:"Error"`
	Code     string   `xml:"Code"`
	Message  string   `xml:"Message"`
	Resource string   `xml:"Resource,omitempty"`
	Request  string   `xml:"RequestId"`
}

func marshalXML(v any) []byte {
	b, _ := xml.Marshal(v)
	return append([]byte(xml.Header), b...)
}

func xmlText(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func listBuckets() []byte {
	names := make([]string, 0, len(fakeObjects))
	for name := range fakeObjects {
		names = append(names, name)
	}
	sort.Strings(names)
	buckets := make([]bucketXML, 0, len(names))
	for _, name := range names {
		buckets = append(buckets, bucketXML{Name: name, CreationDate: creationTime.Format(time.RFC3339Nano)})
	}
	return marshalXML(listBucketsXML{Xmlns: s3Namespace, Owner: ownerXML{ID: "minio", DisplayName: "minio"}, Buckets: buckets})
}

func listObjects(bucket, prefix string) ([]byte, bool) {
	objects, ok := fakeObjects[bucket]
	if !ok {
		return nil, false
	}
	keys := make([]string, 0, len(objects))
	for key := range objects {
		if len(prefix) == 0 || len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	contents := make([]objectXML, 0, len(keys))
	for _, key := range keys {
		o := objects[key]
		contents = append(contents, objectXML{Key: key, LastModified: o.LastModified.Format(time.RFC3339Nano), ETag: "\"" + etag(o.Body) + "\"", Size: len(o.Body), StorageClass: "STANDARD"})
	}
	return marshalXML(listObjectsXML{Xmlns: s3Namespace, Name: bucket, Prefix: prefix, KeyCount: len(contents), MaxKeys: 1000, Contents: contents}), true
}

func s3Error(code, message, resource, requestID string) []byte {
	return marshalXML(errorXML{Code: code, Message: message, Resource: resource, Request: requestID})
}

func deleteObjectsResult(body []byte) []byte {
	var request deleteObjectsRequestXML
	_ = xml.Unmarshal(body, &request)
	result := deleteObjectsResultXML{Xmlns: s3Namespace}
	for _, object := range request.Objects {
		result.Deleted = append(result.Deleted, struct {
			Key string `xml:"Key"`
		}{Key: object.Key})
	}
	return marshalXML(result)
}
