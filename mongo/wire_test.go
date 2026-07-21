package mongo

import (
	"encoding/binary"
	"testing"
)

func TestParseHeader(t *testing.T) {
	raw := make([]byte, 16)
	binary.LittleEndian.PutUint32(raw[0:], 40)    // messageLength
	binary.LittleEndian.PutUint32(raw[4:], 7)     // requestID
	binary.LittleEndian.PutUint32(raw[8:], 0)     // responseTo
	binary.LittleEndian.PutUint32(raw[12:], 2013) // opCode (OP_MSG)

	h, err := parseHeader(raw)
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	if h.messageLength != 40 || h.requestID != 7 || h.responseTo != 0 || h.opCode != opMsg {
		t.Fatalf("header = %+v", h)
	}

	if _, err := parseHeader(raw[:10]); err == nil {
		t.Fatal("parseHeader(short): err = nil, want error")
	}
}

// buildOpMsgRequest frames a body document as a client OP_MSG request payload (the bytes
// after the 16-byte header): flagBits + section kind 0 + body.
func buildOpMsgRequest(body []byte) []byte {
	payload := make([]byte, 4) // flagBits = 0
	payload = append(payload, 0x00)
	payload = append(payload, body...)
	return payload
}

func TestParseOpMsgExtractsBody(t *testing.T) {
	var b bsonBuilder
	b.addInt32("hello", 1)
	b.addString("saslSupportedMechs", "admin.root")
	body := b.build()

	got, err := parseOpMsg(buildOpMsgRequest(body))
	if err != nil {
		t.Fatalf("parseOpMsg: %v", err)
	}
	doc, err := decodeDocument(got)
	if err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if doc.firstKey() != "hello" {
		t.Fatalf("firstKey = %q, want hello", doc.firstKey())
	}
}

// A kind-1 document sequence preceding the body must be skipped, not mis-parsed.
func TestParseOpMsgSkipsDocumentSequence(t *testing.T) {
	var seqDoc bsonBuilder
	seqDoc.addInt32("q", 1)
	seq := seqDoc.build()

	identifier := "documents\x00"
	size := 4 + len(identifier) + len(seq)
	payload := make([]byte, 4) // flagBits
	payload = append(payload, 0x01)
	sizeBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBuf, uint32(size))
	payload = append(payload, sizeBuf...)
	payload = append(payload, identifier...)
	payload = append(payload, seq...)

	var body bsonBuilder
	body.addInt32("insert", 1)
	payload = append(payload, 0x00)
	payload = append(payload, body.build()...)

	got, err := parseOpMsg(payload)
	if err != nil {
		t.Fatalf("parseOpMsg: %v", err)
	}
	doc, err := decodeDocument(got)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.firstKey() != "insert" {
		t.Fatalf("firstKey = %q, want insert", doc.firstKey())
	}
}

func TestParseOpQuery(t *testing.T) {
	var q bsonBuilder
	q.addInt32("isMaster", 1)
	query := q.build()

	payload := make([]byte, 4) // flags
	payload = append(payload, "admin.$cmd\x00"...)
	skip := make([]byte, 8) // numberToSkip + numberToReturn
	payload = append(payload, skip...)
	payload = append(payload, query...)

	collection, gotQuery, err := parseOpQuery(payload)
	if err != nil {
		t.Fatalf("parseOpQuery: %v", err)
	}
	if collection != "admin.$cmd" {
		t.Fatalf("collection = %q, want admin.$cmd", collection)
	}
	doc, err := decodeDocument(gotQuery)
	if err != nil {
		t.Fatalf("decode query: %v", err)
	}
	if doc.firstKey() != "isMaster" {
		t.Fatalf("firstKey = %q, want isMaster", doc.firstKey())
	}
}

// TestBuildOpMsgReplyRoundTrip frames a body as an OP_MSG reply, then re-parses the header
// and body to confirm the whole message is well-formed and echoes responseTo.
func TestBuildOpMsgReplyRoundTrip(t *testing.T) {
	var b bsonBuilder
	b.addBool("ismaster", true)
	b.addDouble("ok", 1.0)
	body := b.build()

	msg := buildOpMsgReply(11, 7, body)

	if int(binary.LittleEndian.Uint32(msg[0:4])) != len(msg) {
		t.Fatalf("messageLength = %d, want %d", binary.LittleEndian.Uint32(msg[0:4]), len(msg))
	}
	h, err := parseHeader(msg[:16])
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	if h.opCode != opMsg {
		t.Fatalf("opCode = %d, want OP_MSG", h.opCode)
	}
	if h.responseTo != 7 {
		t.Fatalf("responseTo = %d, want 7", h.responseTo)
	}

	bodyBytes, err := parseOpMsg(msg[16:])
	if err != nil {
		t.Fatalf("parseOpMsg reply: %v", err)
	}
	doc, err := decodeDocument(bodyBytes)
	if err != nil {
		t.Fatalf("decode reply body: %v", err)
	}
	if v, ok := doc.lookup("ok"); !ok || v.d != 1.0 {
		t.Fatalf("reply ok = %v, want 1.0", v.d)
	}
	if v, ok := doc.lookup("ismaster"); !ok || !v.b {
		t.Fatalf("reply ismaster = %v, want true", v.b)
	}
}

// TestBuildOpReplyRoundTrip does the same for the legacy OP_REPLY framing used to answer
// OP_QUERY isMaster.
func TestBuildOpReplyRoundTrip(t *testing.T) {
	var b bsonBuilder
	b.addBool("ismaster", true)
	b.addDouble("ok", 1.0)
	body := b.build()

	msg := buildOpReply(12, 7, body)

	if int(binary.LittleEndian.Uint32(msg[0:4])) != len(msg) {
		t.Fatalf("messageLength mismatch")
	}
	h, err := parseHeader(msg[:16])
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	if h.opCode != opReply {
		t.Fatalf("opCode = %d, want OP_REPLY", h.opCode)
	}
	if h.responseTo != 7 {
		t.Fatalf("responseTo = %d, want 7", h.responseTo)
	}

	// OP_REPLY body starts after: responseFlags(4) + cursorID(8) + startingFrom(4) + numberReturned(4) = 20 bytes.
	doc, err := decodeDocument(msg[16+20:])
	if err != nil {
		t.Fatalf("decode OP_REPLY body: %v", err)
	}
	if v, ok := doc.lookup("ok"); !ok || v.d != 1.0 {
		t.Fatalf("OP_REPLY ok = %v, want 1.0", v.d)
	}
}
