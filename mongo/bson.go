package mongo

import (
	"encoding/binary"
	"errors"
	"math"
	"time"
)

// BSON element type bytes (subset needed by the honeypot).
const (
	bsonTypeDouble   = 0x01
	bsonTypeString   = 0x02
	bsonTypeDocument = 0x03
	bsonTypeBinary   = 0x05
	bsonTypeBool     = 0x08
	bsonTypeDateTime = 0x09
	bsonTypeNull     = 0x0A
	bsonTypeInt32    = 0x10
	bsonTypeInt64    = 0x12
)

// bsonBuilder accumulates BSON elements in insertion order and frames them into a
// complete document on build(). It is deliberately minimal — only the element types the
// honeypot emits are supported. Order is preserved so the emitted document reads like a
// real server response (ismaster first, ok last, etc.).
type bsonBuilder struct {
	elems []byte
}

func (b *bsonBuilder) key(t byte, name string) {
	b.elems = append(b.elems, t)
	b.elems = append(b.elems, name...)
	b.elems = append(b.elems, 0x00)
}

func (b *bsonBuilder) addDouble(name string, v float64) {
	b.key(bsonTypeDouble, name)
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], math.Float64bits(v))
	b.elems = append(b.elems, buf[:]...)
}

func (b *bsonBuilder) addString(name, v string) {
	b.key(bsonTypeString, name)
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], uint32(len(v)+1))
	b.elems = append(b.elems, buf[:]...)
	b.elems = append(b.elems, v...)
	b.elems = append(b.elems, 0x00)
}

func (b *bsonBuilder) addBool(name string, v bool) {
	b.key(bsonTypeBool, name)
	if v {
		b.elems = append(b.elems, 0x01)
	} else {
		b.elems = append(b.elems, 0x00)
	}
}

func (b *bsonBuilder) addInt32(name string, v int32) {
	b.key(bsonTypeInt32, name)
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], uint32(v))
	b.elems = append(b.elems, buf[:]...)
}

func (b *bsonBuilder) addInt64(name string, v int64) {
	b.key(bsonTypeInt64, name)
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(v))
	b.elems = append(b.elems, buf[:]...)
}

func (b *bsonBuilder) addDateTime(name string, t time.Time) {
	b.key(bsonTypeDateTime, name)
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(t.UnixMilli()))
	b.elems = append(b.elems, buf[:]...)
}

// addDoc appends a nested document. sub must be a complete document (as returned by
// build()).
func (b *bsonBuilder) addDoc(name string, sub []byte) {
	b.key(bsonTypeDocument, name)
	b.elems = append(b.elems, sub...)
}

// addBinary appends a generic (subtype 0x00) binary value.
func (b *bsonBuilder) addBinary(name string, v []byte) {
	b.key(bsonTypeBinary, name)
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], uint32(len(v)))
	b.elems = append(b.elems, buf[:]...)
	b.elems = append(b.elems, 0x00) // subtype: generic
	b.elems = append(b.elems, v...)
}

// build frames the accumulated elements into a complete BSON document:
// int32 total length, elements, trailing 0x00.
func (b *bsonBuilder) build() []byte {
	total := 4 + len(b.elems) + 1
	out := make([]byte, 0, total)
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(total))
	out = append(out, lenBuf[:]...)
	out = append(out, b.elems...)
	out = append(out, 0x00)
	return out
}

// bsonValue is a decoded BSON value. Only the field matching Type is meaningful.
type bsonValue struct {
	Type byte
	d    float64
	str  string
	b    bool
	dt   time.Time
	i32  int32
	i64  int64
	bin  []byte
	doc  bsonDocument
}

type bsonElement struct {
	Key   string
	Value bsonValue
}

// bsonDocument is a decoded document preserving element order.
type bsonDocument []bsonElement

func (d bsonDocument) lookup(key string) (bsonValue, bool) {
	for _, e := range d {
		if e.Key == key {
			return e.Value, true
		}
	}
	return bsonValue{}, false
}

// firstKey returns the key of the first element, which for a command document names the
// command. Empty when the document has no elements.
func (d bsonDocument) firstKey() string {
	if len(d) == 0 {
		return ""
	}
	return d[0].Key
}

var errBSON = errors.New("malformed bson")

// decodeDocument parses a complete BSON document. It validates the declared length and
// every field's bounds so attacker-supplied data can't drive an over-read or panic.
func decodeDocument(data []byte) (bsonDocument, error) {
	if len(data) < 5 {
		return nil, errBSON
	}
	total := int(binary.LittleEndian.Uint32(data[0:4]))
	if total < 5 || total > len(data) {
		return nil, errBSON
	}
	body := data[4 : total-1] // exclude length prefix and trailing null
	if data[total-1] != 0x00 {
		return nil, errBSON
	}

	var doc bsonDocument
	pos := 0
	for pos < len(body) {
		etype := body[pos]
		pos++
		name, n, err := readCString(body[pos:])
		if err != nil {
			return nil, err
		}
		pos += n

		val, consumed, err := decodeValue(etype, body[pos:])
		if err != nil {
			return nil, err
		}
		pos += consumed
		doc = append(doc, bsonElement{Key: name, Value: val})
	}
	return doc, nil
}

func readCString(b []byte) (string, int, error) {
	for i := 0; i < len(b); i++ {
		if b[i] == 0x00 {
			return string(b[:i]), i + 1, nil
		}
	}
	return "", 0, errBSON
}

func decodeValue(etype byte, b []byte) (bsonValue, int, error) {
	switch etype {
	case bsonTypeDouble:
		if len(b) < 8 {
			return bsonValue{}, 0, errBSON
		}
		return bsonValue{Type: etype, d: math.Float64frombits(binary.LittleEndian.Uint64(b[:8]))}, 8, nil
	case bsonTypeString:
		if len(b) < 4 {
			return bsonValue{}, 0, errBSON
		}
		slen := int(binary.LittleEndian.Uint32(b[:4]))
		if slen < 1 || 4+slen > len(b) {
			return bsonValue{}, 0, errBSON
		}
		// slen includes the trailing null.
		return bsonValue{Type: etype, str: string(b[4 : 4+slen-1])}, 4 + slen, nil
	case bsonTypeDocument:
		if len(b) < 4 {
			return bsonValue{}, 0, errBSON
		}
		dlen := int(binary.LittleEndian.Uint32(b[:4]))
		if dlen < 5 || dlen > len(b) {
			return bsonValue{}, 0, errBSON
		}
		sub, err := decodeDocument(b[:dlen])
		if err != nil {
			return bsonValue{}, 0, err
		}
		return bsonValue{Type: etype, doc: sub}, dlen, nil
	case bsonTypeBinary:
		if len(b) < 5 {
			return bsonValue{}, 0, errBSON
		}
		blen := int(binary.LittleEndian.Uint32(b[:4]))
		if blen < 0 || 5+blen > len(b) {
			return bsonValue{}, 0, errBSON
		}
		// b[4] is the subtype; skip it and copy the payload.
		payload := append([]byte(nil), b[5:5+blen]...)
		return bsonValue{Type: etype, bin: payload}, 5 + blen, nil
	case bsonTypeBool:
		if len(b) < 1 {
			return bsonValue{}, 0, errBSON
		}
		return bsonValue{Type: etype, b: b[0] != 0x00}, 1, nil
	case bsonTypeDateTime:
		if len(b) < 8 {
			return bsonValue{}, 0, errBSON
		}
		ms := int64(binary.LittleEndian.Uint64(b[:8]))
		return bsonValue{Type: etype, dt: time.UnixMilli(ms).UTC()}, 8, nil
	case bsonTypeNull:
		return bsonValue{Type: etype}, 0, nil
	case bsonTypeInt32:
		if len(b) < 4 {
			return bsonValue{}, 0, errBSON
		}
		return bsonValue{Type: etype, i32: int32(binary.LittleEndian.Uint32(b[:4]))}, 4, nil
	case bsonTypeInt64:
		if len(b) < 8 {
			return bsonValue{}, 0, errBSON
		}
		return bsonValue{Type: etype, i64: int64(binary.LittleEndian.Uint64(b[:8]))}, 8, nil
	default:
		// Unknown/unsupported type: we can't know its length, so we cannot safely continue.
		return bsonValue{}, 0, errBSON
	}
}
