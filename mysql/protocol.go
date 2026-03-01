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
	buf := make([]byte, 0, 32)
	buf = append(buf, 0x00) // OK marker
	buf = appendLengthEncodedInt(buf, affectedRows)
	buf = appendLengthEncodedInt(buf, lastInsertID)
	// status flags: SERVER_STATUS_AUTOCOMMIT
	buf = append(buf, 0x02, 0x00)
	// warnings
	buf = append(buf, 0x00, 0x00)
	return writePacket(w, seqID, buf)
}

func writeERRPacket(w io.Writer, seqID uint8, code uint16, state, message string) error {
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
	buf = append(buf, message...)
	return writePacket(w, seqID, buf)
}

func writeEOFPacket(w io.Writer, seqID uint8) error {
	buf := []byte{
		0xFE,       // EOF marker
		0x00, 0x00, // warnings
		0x02, 0x00, // status: SERVER_STATUS_AUTOCOMMIT
	}
	return writePacket(w, seqID, buf)
}

type columnDef struct {
	Name     string
	ColType  byte
	MaxLen   uint32
}

func writeResultSet(w io.Writer, seqID uint8, columns []columnDef, rows [][]string) (uint8, error) {
	// Column count
	buf := appendLengthEncodedInt(nil, uint64(len(columns)))
	if err := writePacket(w, seqID, buf); err != nil {
		return seqID, err
	}
	seqID++

	// Column definitions
	for _, col := range columns {
		def := buildColumnDef(col)
		if err := writePacket(w, seqID, def); err != nil {
			return seqID, err
		}
		seqID++
	}

	// EOF after columns
	if err := writeEOFPacket(w, seqID); err != nil {
		return seqID, err
	}
	seqID++

	// Rows
	for _, row := range rows {
		rowBuf := make([]byte, 0, 128)
		for _, val := range row {
			rowBuf = appendLengthEncodedString(rowBuf, val)
		}
		if err := writePacket(w, seqID, rowBuf); err != nil {
			return seqID, err
		}
		seqID++
	}

	// EOF after rows
	if err := writeEOFPacket(w, seqID); err != nil {
		return seqID, err
	}
	seqID++

	return seqID, nil
}

func buildColumnDef(col columnDef) []byte {
	buf := make([]byte, 0, 128)
	buf = appendLengthEncodedString(buf, "def")   // catalog
	buf = appendLengthEncodedString(buf, "")       // schema
	buf = appendLengthEncodedString(buf, "")       // table
	buf = appendLengthEncodedString(buf, "")       // org_table
	buf = appendLengthEncodedString(buf, col.Name) // name
	buf = appendLengthEncodedString(buf, col.Name) // org_name
	buf = append(buf, 0x0c)                        // length of fixed fields
	buf = append(buf, 0x2d, 0x00)                  // charset: utf8mb4 (45)

	maxLen := col.MaxLen
	if maxLen == 0 {
		maxLen = 255
	}
	lenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBytes, maxLen)
	buf = append(buf, lenBytes...)

	buf = append(buf, col.ColType) // column type (0xFD = VARCHAR)
	buf = append(buf, 0x00, 0x00) // flags
	buf = append(buf, 0x00)       // decimals
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
