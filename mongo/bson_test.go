package mongo

import (
	"bytes"
	"testing"
	"time"
)

// TestEncodeOkExactBytes pins the wire encoding of a minimal {"ok": 1.0} document so a
// refactor that breaks BSON framing fails loudly.
func TestEncodeOkExactBytes(t *testing.T) {
	var b bsonBuilder
	b.addDouble("ok", 1.0)
	got := b.build()

	want := []byte{
		0x11, 0x00, 0x00, 0x00, // int32 total length = 17
		0x01,             // type: double
		0x6F, 0x6B, 0x00, // cstring "ok"
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F, // float64 1.0 LE
		0x00, // document terminator
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("encode {ok:1.0}\n got  %x\n want %x", got, want)
	}
}

// TestEncodeDecodeRoundTrip builds a document with every type the honeypot emits or reads,
// then decodes it back and checks each value survives the round trip.
func TestEncodeDecodeRoundTrip(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()

	var sub bsonBuilder
	sub.addString("name", "mongo-go-driver")
	sub.addString("version", "1.13.1")

	var b bsonBuilder
	b.addBool("ismaster", true)
	b.addInt32("maxWireVersion", 21)
	b.addInt64("counter", 9000000000)
	b.addString("version", "7.0.5")
	b.addDateTime("localTime", now)
	b.addDouble("ok", 1.0)
	b.addDoc("driver", sub.build())
	b.addBinary("payload", []byte{0x01, 0x02, 0x03})

	doc, err := decodeDocument(b.build())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if v, ok := doc.lookup("ismaster"); !ok || v.b != true {
		t.Errorf("ismaster = %v (ok=%v), want true", v.b, ok)
	}
	if v, ok := doc.lookup("maxWireVersion"); !ok || v.i32 != 21 {
		t.Errorf("maxWireVersion = %v, want 21", v.i32)
	}
	if v, ok := doc.lookup("counter"); !ok || v.i64 != 9000000000 {
		t.Errorf("counter = %v, want 9000000000", v.i64)
	}
	if v, ok := doc.lookup("version"); !ok || v.str != "7.0.5" {
		t.Errorf("version = %q, want 7.0.5", v.str)
	}
	if v, ok := doc.lookup("ok"); !ok || v.d != 1.0 {
		t.Errorf("ok = %v, want 1.0", v.d)
	}
	if v, ok := doc.lookup("localTime"); !ok || v.dt.UTC() != now {
		t.Errorf("localTime = %v, want %v", v.dt, now)
	}
	if v, ok := doc.lookup("payload"); !ok || !bytes.Equal(v.bin, []byte{0x01, 0x02, 0x03}) {
		t.Errorf("payload = %x, want 010203", v.bin)
	}

	sv, ok := doc.lookup("driver")
	if !ok {
		t.Fatal("driver subdocument missing")
	}
	if dv, ok := sv.doc.lookup("version"); !ok || dv.str != "1.13.1" {
		t.Errorf("driver.version = %q, want 1.13.1", dv.str)
	}
}

// TestFirstKey exercises command-name extraction: the first element key names the command.
func TestFirstKey(t *testing.T) {
	var b bsonBuilder
	b.addInt32("hello", 1)
	b.addInt32("helloOk", 1)
	doc, err := decodeDocument(b.build())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := doc.firstKey(); got != "hello" {
		t.Fatalf("firstKey = %q, want hello", got)
	}
}

// TestDecodeRejectsTruncated ensures a malformed length header is rejected rather than
// panicking or over-reading.
func TestDecodeRejectsTruncated(t *testing.T) {
	if _, err := decodeDocument([]byte{0x20, 0x00, 0x00, 0x00, 0x01}); err == nil {
		t.Fatal("decode truncated document: err = nil, want error")
	}
	if _, err := decodeDocument([]byte{0x03}); err == nil {
		t.Fatal("decode short buffer: err = nil, want error")
	}
}
