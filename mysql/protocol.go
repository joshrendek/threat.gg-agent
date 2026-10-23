package mysql

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

// MySQL packet format: [3-byte payload length (LE)][1-byte sequence_id][payload]
const maxPacketSize = 1 << 20 // 1MB cap to prevent memory exhaustion

func readPacket(r io.Reader) ([]byte, uint8, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, 0, err
	}

	length := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
	seqID := header[3]

	if length < 0 || length > maxPacketSize {
		return nil, 0, fmt.Errorf("packet too large: %d", length)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, 0, err
	}

	return payload, seqID, nil
}

func writePacket(w io.Writer, seqID uint8, payload []byte) error {
	length := len(payload)
	header := []byte{
		byte(length),
		byte(length >> 8),
		byte(length >> 16),
		seqID,
	}
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func writeOKPacket(w io.Writer, seqID uint8, affectedRows, lastInsertID uint64) error {
	return writePacket(w, seqID, okPayload(0x00, affectedRows, lastInsertID))
}

func writeERRPacket(w io.Writer, seqID uint8, code uint16, state, message string) error {
	return writePacket(w, seqID, errPayload(code, state, message))
}

// errPayload is an ERR packet (CLIENT_PROTOCOL_41 form, with the SQLSTATE marker).
func errPayload(code uint16, state, message string) []byte {
	buf := make([]byte, 0, 64)
	buf = append(buf, 0xFF) // ERR marker
	buf = append(buf, byte(code), byte(code>>8))
	buf = append(buf, '#')
	if len(state) >= 5 {
		buf = append(buf, state[:5]...)
	} else {
		padded := state + "     "
		buf = append(buf, padded[:5]...)
	}
	return append(buf, message...)
}

// Column definition flags (include/mysql_com.h) and the binary charset.
const (
	flagUnsigned uint16 = 0x0020
	flagBlob     uint16 = 0x0010
	flagBinary   uint16 = 0x0080

	charsetBinary uint16 = 63
)

// maxPayload is the largest payload one packet carries; a longer one would
// have to be split, which no reply this honeypot builds needs.
const maxPayload = 1<<24 - 1

type columnDef struct {
	Name    string
	ColType byte
	MaxLen  uint32 // column length; 0 means 255
	// Charset is the column's collation id; 0 means the connection's utf8mb4
	// (charsetUTF8MB4, the collation the handshake advertises). Numeric and
	// temporal columns use charsetBinary, as MySQL does.
	Charset  uint16
	Flags    uint16
	Decimals byte
}

// textRows turns built-in string rows into encoder rows (no NULLs).
func textRows(rows [][]string) [][]*string {
	out := make([][]*string, len(rows))
	for i, row := range rows {
		out[i] = make([]*string, len(row))
		for j := range row {
			out[i][j] = &row[j]
		}
	}
	return out
}

// writeResultSet writes a text-protocol result set framed for the session:
// see encodeResultSet.
func writeResultSet(w io.Writer, seqID uint8, columns []columnDef, rows [][]string, deprecateEOF bool) (uint8, error) {
	b, next, ok := encodeResultSet(seqID, columns, textRows(rows), deprecateEOF)
	if !ok {
		return seqID, fmt.Errorf("result set packet exceeds %d bytes", maxPayload)
	}
	_, err := w.Write(b)
	return next, err
}

// encodeResultSet builds a whole text-protocol result set starting at seqID
// and returns it with the next sequence id. A nil cell is SQL NULL (0xFB).
//
// With CLIENT_DEPRECATE_EOF negotiated there is no EOF packet between the
// column definitions and the rows, and the rows end with an OK packet that
// carries the 0xFE header; without it, classic EOF packets do both jobs. A
// client reads a packet the other way round as the end of the result set and
// loses sync with every later reply.
//
// ok is false when a packet would need splitting (a payload of 16 MiB or more).
func encodeResultSet(seqID uint8, columns []columnDef, rows [][]*string, deprecateEOF bool) ([]byte, uint8, bool) {
	var out []byte
	ok := true
	add := func(payload []byte) {
		if len(payload) >= maxPayload {
			ok = false
			return
		}
		out = appendPacket(out, seqID, payload)
		seqID++
	}
	add(appendLengthEncodedInt(nil, uint64(len(columns))))
	for _, col := range columns {
		add(buildColumnDef(col))
	}
	if !deprecateEOF {
		add(eofPayload())
	}
	for _, row := range rows {
		rowBuf := make([]byte, 0, 128)
		for _, val := range row {
			if val == nil {
				rowBuf = append(rowBuf, 0xFB)
				continue
			}
			rowBuf = appendLengthEncodedString(rowBuf, *val)
		}
		add(rowBuf)
	}
	if deprecateEOF {
		add(okPayload(0xFE, 0, 0))
	} else {
		add(eofPayload())
	}
	if !ok {
		return nil, seqID, false
	}
	return out, seqID, true
}

// appendPacket appends one packet: 3-byte little-endian length, sequence id, payload.
func appendPacket(dst []byte, seqID uint8, payload []byte) []byte {
	n := len(payload)
	dst = append(dst, byte(n), byte(n>>8), byte(n>>16), seqID)
	return append(dst, payload...)
}

// okPayload is an OK packet with the given header: 0x00, or 0xFE for the OK
// that ends a row stream under CLIENT_DEPRECATE_EOF.
func okPayload(header byte, affectedRows, lastInsertID uint64) []byte {
	buf := []byte{header}
	buf = appendLengthEncodedInt(buf, affectedRows)
	buf = appendLengthEncodedInt(buf, lastInsertID)
	buf = append(buf, byte(serverStatusAutocommit), byte(serverStatusAutocommit>>8))
	return append(buf, 0x00, 0x00) // warnings
}

// eofPayload is a classic EOF packet: 0 warnings, AUTOCOMMIT.
func eofPayload() []byte {
	return []byte{0xFE, 0x00, 0x00, byte(serverStatusAutocommit), byte(serverStatusAutocommit >> 8)}
}

func buildColumnDef(col columnDef) []byte {
	buf := make([]byte, 0, 128)
	buf = appendLengthEncodedString(buf, "def")    // catalog
	buf = appendLengthEncodedString(buf, "")       // schema
	buf = appendLengthEncodedString(buf, "")       // table
	buf = appendLengthEncodedString(buf, "")       // org_table
	buf = appendLengthEncodedString(buf, col.Name) // name
	buf = appendLengthEncodedString(buf, col.Name) // org_name
	buf = append(buf, 0x0c)                        // length of fixed fields

	charset := col.Charset
	if charset == 0 {
		charset = uint16(charsetUTF8MB4)
	}
	buf = binary.LittleEndian.AppendUint16(buf, charset)

	maxLen := col.MaxLen
	if maxLen == 0 {
		maxLen = 255
	}
	buf = binary.LittleEndian.AppendUint32(buf, maxLen)

	buf = append(buf, col.ColType) // column type (0xFD = VAR_STRING)
	buf = binary.LittleEndian.AppendUint16(buf, col.Flags)
	buf = append(buf, col.Decimals)
	buf = append(buf, 0x00, 0x00) // filler
	return buf
}

// Length-encoded integer encoding
func appendLengthEncodedInt(buf []byte, n uint64) []byte {
	switch {
	case n < 251:
		return append(buf, byte(n))
	case n < 1<<16:
		return append(buf, 0xFC, byte(n), byte(n>>8))
	case n < 1<<24:
		return append(buf, 0xFD, byte(n), byte(n>>8), byte(n>>16))
	default:
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, n)
		return append(append(buf, 0xFE), b...)
	}
}

func decodeLengthEncodedInt(data []byte, offset int) (uint64, int) {
	if offset >= len(data) {
		return 0, offset
	}
	switch {
	case data[offset] < 0xFB:
		return uint64(data[offset]), offset + 1
	case data[offset] == 0xFC:
		if offset+2 >= len(data) {
			return 0, len(data)
		}
		return uint64(binary.LittleEndian.Uint16(data[offset+1:])), offset + 3
	case data[offset] == 0xFD:
		if offset+3 >= len(data) {
			return 0, len(data)
		}
		return uint64(data[offset+1]) | uint64(data[offset+2])<<8 | uint64(data[offset+3])<<16, offset + 4
	case data[offset] == 0xFE:
		if offset+8 >= len(data) {
			return 0, len(data)
		}
		return binary.LittleEndian.Uint64(data[offset+1:]), offset + 9
	default: // 0xFB = NULL, 0xFF = ERR
		return math.MaxUint64, offset + 1
	}
}

func appendLengthEncodedString(buf []byte, s string) []byte {
	buf = appendLengthEncodedInt(buf, uint64(len(s)))
	return append(buf, s...)
}

func decodeLengthEncodedString(data []byte, offset int) (string, int) {
	length, newOffset := decodeLengthEncodedInt(data, offset)
	if length == math.MaxUint64 {
		return "", newOffset
	}
	end := newOffset + int(length)
	if end > len(data) {
		return "", len(data)
	}
	return string(data[newOffset:end]), end
}
