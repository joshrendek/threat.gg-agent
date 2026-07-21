package mongo

import (
	"encoding/binary"
	"errors"
)

// MongoDB wire-protocol opcodes (the subset this honeypot understands).
const (
	opReply = 1    // response to a legacy OP_QUERY
	opQuery = 2004 // legacy query (isMaster handshake)
	opMsg   = 2013 // modern command message
)

const (
	headerLen = 16
	// maxMessageLen bounds a single accepted wire message so a hostile 4-byte length
	// prefix cannot drive a large up-front allocation pinned across a stalled connection.
	// A honeypot never needs to accept large messages (real handshakes are well under a
	// KB), so this is intentionally far below the advertised maxMessageSizeBytes — the
	// value we *claim* to support (commands.go) and the value we *accept* are independent.
	maxMessageLen = 1 << 20 // 1 MiB
)

var errWire = errors.New("malformed mongo wire message")

// msgHeader is the 16-byte MongoDB wire-protocol message header.
type msgHeader struct {
	messageLength int32
	requestID     int32
	responseTo    int32
	opCode        int32
}

// parseHeader decodes the 16-byte wire header (little-endian).
func parseHeader(b []byte) (msgHeader, error) {
	if len(b) < headerLen {
		return msgHeader{}, errWire
	}
	return msgHeader{
		messageLength: int32(binary.LittleEndian.Uint32(b[0:4])),
		requestID:     int32(binary.LittleEndian.Uint32(b[4:8])),
		responseTo:    int32(binary.LittleEndian.Uint32(b[8:12])),
		opCode:        int32(binary.LittleEndian.Uint32(b[12:16])),
	}, nil
}

// parseOpMsg returns the kind-0 body document bytes from an OP_MSG payload (the bytes
// after the 16-byte header). Kind-1 document sequences are skipped; a trailing checksum,
// if present, is harmless because scanning stops at the body section.
func parseOpMsg(payload []byte) ([]byte, error) {
	if len(payload) < 4 {
		return nil, errWire
	}
	pos := 4 // skip flagBits
	for pos < len(payload) {
		kind := payload[pos]
		pos++
		switch kind {
		case 0: // body: a single document
			return readEmbeddedDoc(payload[pos:])
		case 1: // document sequence: int32 size (incl. itself) + cstring + docs
			if pos+4 > len(payload) {
				return nil, errWire
			}
			size := int(binary.LittleEndian.Uint32(payload[pos : pos+4]))
			if size < 4 || pos+size > len(payload) {
				return nil, errWire
			}
			pos += size
		default:
			return nil, errWire
		}
	}
	return nil, errWire
}

// readEmbeddedDoc slices out one complete BSON document from the front of b using its own
// length prefix, validating bounds.
func readEmbeddedDoc(b []byte) ([]byte, error) {
	if len(b) < 4 {
		return nil, errWire
	}
	dlen := int(binary.LittleEndian.Uint32(b[:4]))
	if dlen < 5 || dlen > len(b) {
		return nil, errWire
	}
	return b[:dlen], nil
}

// parseOpQuery extracts the fullCollectionName and the query document from an OP_QUERY
// payload (the bytes after the 16-byte header):
// flags int32, fullCollectionName cstring, numberToSkip int32, numberToReturn int32, query.
func parseOpQuery(payload []byte) (string, []byte, error) {
	if len(payload) < 4 {
		return "", nil, errWire
	}
	pos := 4 // skip flags
	name, n, err := readCString(payload[pos:])
	if err != nil {
		return "", nil, err
	}
	pos += n
	pos += 8 // numberToSkip + numberToReturn
	if pos > len(payload) {
		return "", nil, errWire
	}
	query, err := readEmbeddedDoc(payload[pos:])
	if err != nil {
		return "", nil, err
	}
	return name, query, nil
}

// buildOpMsgReply frames a body document as an OP_MSG reply (flagBits 0, single kind-0
// section), echoing responseTo so the client correlates it to its request.
func buildOpMsgReply(requestID, responseTo int32, body []byte) []byte {
	total := headerLen + 4 + 1 + len(body)
	out := make([]byte, 0, total)
	out = appendHeader(out, int32(total), requestID, responseTo, opMsg)
	out = binary.LittleEndian.AppendUint32(out, 0) // flagBits
	out = append(out, 0x00)                        // section kind: body
	out = append(out, body...)
	return out
}

// buildOpReply frames a body document as a legacy OP_REPLY answering an OP_QUERY.
func buildOpReply(requestID, responseTo int32, body []byte) []byte {
	total := headerLen + 4 + 8 + 4 + 4 + len(body)
	out := make([]byte, 0, total)
	out = appendHeader(out, int32(total), requestID, responseTo, opReply)
	out = binary.LittleEndian.AppendUint32(out, 0) // responseFlags
	out = binary.LittleEndian.AppendUint64(out, 0) // cursorID
	out = binary.LittleEndian.AppendUint32(out, 0) // startingFrom
	out = binary.LittleEndian.AppendUint32(out, 1) // numberReturned
	out = append(out, body...)
	return out
}

func appendHeader(out []byte, messageLength, requestID, responseTo, opCode int32) []byte {
	out = binary.LittleEndian.AppendUint32(out, uint32(messageLength))
	out = binary.LittleEndian.AppendUint32(out, uint32(requestID))
	out = binary.LittleEndian.AppendUint32(out, uint32(responseTo))
	out = binary.LittleEndian.AppendUint32(out, uint32(opCode))
	return out
}
