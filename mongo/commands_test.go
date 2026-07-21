package mongo

import "testing"

func decodeOrFail(t *testing.T, raw []byte) bsonDocument {
	t.Helper()
	doc, err := decodeDocument(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return doc
}

func TestHelloResponseFields(t *testing.T) {
	doc := decodeOrFail(t, helloResponse())

	if v, ok := doc.lookup("ismaster"); !ok || !v.b {
		t.Errorf("ismaster = %v, want true", v.b)
	}
	if v, ok := doc.lookup("isWritablePrimary"); !ok || !v.b {
		t.Errorf("isWritablePrimary = %v, want true", v.b)
	}
	if v, ok := doc.lookup("maxWireVersion"); !ok || v.i32 != 21 {
		t.Errorf("maxWireVersion = %d, want 21", v.i32)
	}
	if v, ok := doc.lookup("maxBsonObjectSize"); !ok || v.i32 != 16*1024*1024 {
		t.Errorf("maxBsonObjectSize = %d, want 16MiB", v.i32)
	}
	if v, ok := doc.lookup("maxMessageSizeBytes"); !ok || v.i32 != 48000000 {
		t.Errorf("maxMessageSizeBytes = %d", v.i32)
	}
	if _, ok := doc.lookup("localTime"); !ok {
		t.Error("localTime missing")
	}
	if v, ok := doc.lookup("ok"); !ok || v.d != 1.0 {
		t.Errorf("ok = %v, want 1.0", v.d)
	}
}

func TestBuildInfoResponseHasVersion(t *testing.T) {
	doc := decodeOrFail(t, buildInfoResponse())
	if v, ok := doc.lookup("version"); !ok || v.str != serverVersion {
		t.Errorf("version = %q, want %q", v.str, serverVersion)
	}
	if v, ok := doc.lookup("ok"); !ok || v.d != 1.0 {
		t.Errorf("ok = %v, want 1.0", v.d)
	}
}

func TestExtractCredentialsScram(t *testing.T) {
	var b bsonBuilder
	b.addInt32("saslStart", 1)
	b.addString("mechanism", "SCRAM-SHA-256")
	b.addBinary("payload", []byte("n,,n=root,r=rOprNGfwEbeRWgbNEkqO"))
	doc := decodeOrFail(t, b.build())

	user, pass, mech := extractCredentials("saslStart", doc)
	if user != "root" {
		t.Errorf("user = %q, want root", user)
	}
	if pass != "" {
		t.Errorf("pass = %q, want empty (scram hides password)", pass)
	}
	if mech != "SCRAM-SHA-256" {
		t.Errorf("mech = %q", mech)
	}
}

func TestExtractCredentialsPlain(t *testing.T) {
	var b bsonBuilder
	b.addInt32("saslStart", 1)
	b.addString("mechanism", "PLAIN")
	b.addBinary("payload", []byte("\x00admin\x00s3cr3t"))
	doc := decodeOrFail(t, b.build())

	user, pass, _ := extractCredentials("saslStart", doc)
	if user != "admin" {
		t.Errorf("user = %q, want admin", user)
	}
	if pass != "s3cr3t" {
		t.Errorf("pass = %q, want s3cr3t", pass)
	}
}

func TestExtractCredentialsAuthenticate(t *testing.T) {
	var b bsonBuilder
	b.addInt32("authenticate", 1)
	b.addString("user", "dbadmin")
	b.addString("mechanism", "MONGODB-X509")
	doc := decodeOrFail(t, b.build())

	user, _, mech := extractCredentials("authenticate", doc)
	if user != "dbadmin" {
		t.Errorf("user = %q, want dbadmin", user)
	}
	if mech != "MONGODB-X509" {
		t.Errorf("mech = %q", mech)
	}
}

func TestExtractClientVersion(t *testing.T) {
	var driver bsonBuilder
	driver.addString("name", "mongo-go-driver")
	driver.addString("version", "1.13.1")

	var client bsonBuilder
	client.addDoc("driver", driver.build())

	var b bsonBuilder
	b.addInt32("hello", 1)
	b.addDoc("client", client.build())
	doc := decodeOrFail(t, b.build())

	if got := extractClientVersion(doc); got != "mongo-go-driver 1.13.1" {
		t.Errorf("clientVersion = %q, want 'mongo-go-driver 1.13.1'", got)
	}

	// Absent client metadata yields empty string, not a panic.
	empty := decodeOrFail(t, (&bsonBuilder{}).build())
	if got := extractClientVersion(empty); got != "" {
		t.Errorf("clientVersion(empty) = %q, want empty", got)
	}
}

func TestCommandResponseDispatch(t *testing.T) {
	tests := []struct {
		cmd    string
		verify func(t *testing.T, doc bsonDocument)
	}{
		{"hello", func(t *testing.T, doc bsonDocument) {
			if v, ok := doc.lookup("ismaster"); !ok || !v.b {
				t.Error("hello: ismaster not true")
			}
		}},
		{"isMaster", func(t *testing.T, doc bsonDocument) {
			if v, ok := doc.lookup("ismaster"); !ok || !v.b {
				t.Error("isMaster: ismaster not true")
			}
		}},
		{"ping", func(t *testing.T, doc bsonDocument) {
			if v, ok := doc.lookup("ok"); !ok || v.d != 1.0 {
				t.Error("ping: ok != 1.0")
			}
		}},
		{"buildInfo", func(t *testing.T, doc bsonDocument) {
			if v, ok := doc.lookup("version"); !ok || v.str != serverVersion {
				t.Error("buildInfo: version missing")
			}
		}},
		{"saslStart", func(t *testing.T, doc bsonDocument) {
			if v, ok := doc.lookup("ok"); !ok || v.d != 0.0 {
				t.Error("saslStart: ok should be 0 (auth failed)")
			}
			if _, ok := doc.lookup("errmsg"); !ok {
				t.Error("saslStart: errmsg missing")
			}
		}},
		{"whatsmyuri", func(t *testing.T, doc bsonDocument) {
			if v, ok := doc.lookup("ok"); !ok || v.d != 1.0 {
				t.Error("whatsmyuri: ok != 1.0")
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			var b bsonBuilder
			b.addInt32(tt.cmd, 1)
			body := commandResponse(tt.cmd, decodeOrFail(t, b.build()))
			tt.verify(t, decodeOrFail(t, body))
		})
	}
}
