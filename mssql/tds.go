package mssql

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
)

const (
	packetSQLBatch = 0x01
	packetRPC      = 0x03
	packetReply    = 0x04
	packetLogin7   = 0x10
	packetPrelogin = 0x12
	statusEOM      = 0x01

	maxPacketSize  = 64 << 10
	maxMessageSize = 1 << 20
)

type packetHeader struct {
	typeID   byte
	status   byte
	length   uint16
	spid     uint16
	packetID byte
}

func readMessage(r io.Reader) (byte, []byte, error) {
	var message []byte
	var messageType byte
	for {
		headerBytes := make([]byte, 8)
		if _, err := io.ReadFull(r, headerBytes); err != nil {
			return 0, nil, err
		}
		h := packetHeader{
			typeID: headerBytes[0], status: headerBytes[1],
			length: binary.BigEndian.Uint16(headerBytes[2:4]),
			spid:   binary.BigEndian.Uint16(headerBytes[4:6]), packetID: headerBytes[6],
		}
		if h.length < 8 || int(h.length) > maxPacketSize {
			return 0, nil, fmt.Errorf("invalid TDS packet length %d", h.length)
		}
		if len(message) == 0 {
			messageType = h.typeID
		} else if h.typeID != messageType {
			return 0, nil, errors.New("TDS message changed packet type")
		}
		payloadLen := int(h.length) - 8
		if payloadLen > maxMessageSize-len(message) {
			return 0, nil, errors.New("TDS message exceeds limit")
		}
		start := len(message)
		message = append(message, make([]byte, payloadLen)...)
		if _, err := io.ReadFull(r, message[start:]); err != nil {
			return 0, nil, err
		}
		if h.status&statusEOM != 0 {
			return messageType, message, nil
		}
	}
}

func writeMessage(w io.Writer, typeID byte, payload []byte) error {
	if len(payload) > maxMessageSize {
		return errors.New("TDS response exceeds limit")
	}
	packetID := byte(1)
	for len(payload) > 0 || packetID == 1 {
		partLen := len(payload)
		if partLen > maxPacketSize-8 {
			partLen = maxPacketSize - 8
		}
		status := byte(0)
		if partLen == len(payload) {
			status = statusEOM
		}
		header := []byte{typeID, status, 0, 0, 0, 0, packetID, 0}
		binary.BigEndian.PutUint16(header[2:4], uint16(partLen+8))
		if _, err := w.Write(header); err != nil {
			return err
		}
		if partLen > 0 {
			if _, err := w.Write(payload[:partLen]); err != nil {
				return err
			}
			payload = payload[partLen:]
		}
		packetID++
	}
	return nil
}

func preloginResponse() []byte {
	// Tokens 0x00-0x04 advertise VERSION, ENCRYPTION, INSTOPT, THREADID and
	// MARS respectively. Offsets are from the
	// beginning of the PRELOGIN payload, including this option table.
	return []byte{
		0x00, 0x00, 0x1a, 0x00, 0x06,
		0x01, 0x00, 0x20, 0x00, 0x01,
		0x02, 0x00, 0x21, 0x00, 0x01,
		0x03, 0x00, 0x22, 0x00, 0x04,
		0x04, 0x00, 0x26, 0x00, 0x01,
		0xff,
		0x10, 0x00, 0x03, 0xe8, 0x00, 0x00, // SQL Server 16.0.1000
		0x02,                   // ENCRYPT_NOT_SUP
		0x00,                   // default instance
		0x00, 0x00, 0x00, 0x00, // thread id
		0x00, // MARS disabled
	}
}

type loginRecord struct {
	username, password, hostname, appName, serverName, library, database string
	tdsVersion                                                           uint32
}

func parseLogin7(payload []byte) (loginRecord, error) {
	if len(payload) < 94 {
		return loginRecord{}, errors.New("short LOGIN7 record")
	}
	declared := int(binary.LittleEndian.Uint32(payload[:4]))
	if declared < 94 || declared > len(payload) {
		return loginRecord{}, errors.New("invalid LOGIN7 length")
	}
	readRawField := func(pairOffset int) ([]byte, error) {
		offset := int(binary.LittleEndian.Uint16(payload[pairOffset : pairOffset+2]))
		chars := int(binary.LittleEndian.Uint16(payload[pairOffset+2 : pairOffset+4]))
		byteLen := chars * 2
		if chars > 4096 || offset < 0 || byteLen > declared-offset {
			return nil, errors.New("invalid LOGIN7 field bounds")
		}
		return payload[offset : offset+byteLen], nil
	}
	fields := make([]string, 7)
	var err error
	for i, off := range []int{36, 40, 44, 48, 52, 60, 68} {
		var raw []byte
		raw, err = readRawField(off)
		if err != nil {
			return loginRecord{}, err
		}
		if off == 44 {
			fields[i] = decodePassword(raw)
		} else {
			fields[i] = decodeUCS2(raw)
		}
	}
	return loginRecord{
		hostname: fields[0], username: fields[1], password: fields[2],
		appName: fields[3], serverName: fields[4], library: fields[5], database: fields[6],
		tdsVersion: binary.LittleEndian.Uint32(payload[4:8]),
	}, nil
}

func decodePassword(raw []byte) string {
	raw = append([]byte(nil), raw...)
	for i := range raw {
		b := raw[i] ^ 0xa5
		raw[i] = b<<4 | b>>4
	}
	return decodeUCS2(raw)
}

func decodeUCS2(b []byte) string {
	units := make([]uint16, 0, len(b)/2)
	for len(b) >= 2 {
		units = append(units, binary.LittleEndian.Uint16(b[:2]))
		b = b[2:]
	}
	return string(utf16.Decode(units))
}

func encodeUCS2(s string) []byte {
	units := utf16.Encode([]rune(s))
	b := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(b[i*2:], unit)
	}
	return b
}

func appendU16(dst []byte, value uint16) []byte {
	return binary.LittleEndian.AppendUint16(dst, value)
}

func appendU32(dst []byte, value uint32) []byte {
	return binary.LittleEndian.AppendUint32(dst, value)
}

func appendU64(dst []byte, value uint64) []byte {
	return binary.LittleEndian.AppendUint64(dst, value)
}

func bVarChar(s string) []byte {
	runes := []rune(s)
	if len(runes) > 255 {
		runes = runes[:255]
	}
	return append([]byte{byte(len(runes))}, encodeUCS2(string(runes))...)
}

func postLoginResponse(envDatabase string) []byte {
	if envDatabase == "" {
		envDatabase = "master"
	}
	// LOGINACK: SQL_TSQL + TDS 7.4 + program name + 16.0.1000.6.
	body := []byte{0x01, 0x74, 0x00, 0x00, 0x04}
	body = append(body, bVarChar("Microsoft SQL Server")...)
	body = append(body, 16, 0, 0x03, 0xe8)
	payload := []byte{0xad}
	payload = appendU16(payload, uint16(len(body)))
	payload = append(payload, body...)

	newDB := bVarChar(envDatabase)
	oldDB := bVarChar("")
	envBody := append([]byte{0x01}, append(newDB, oldDB...)...)
	payload = append(payload, 0xe3)
	payload = appendU16(payload, uint16(len(envBody)))
	payload = append(payload, envBody...)
	return appendDone(payload, 0, 0)
}

func appendDone(dst []byte, status uint16, rowCount uint64) []byte {
	dst = append(dst, 0xfd)
	dst = appendU16(dst, status)
	dst = appendU16(dst, 0)
	return appendU64(dst, rowCount)
}

func resultResponse(column string, rows []string) []byte {
	if column == "" {
		column = "result"
	}
	payload := []byte{0x81}
	payload = appendU16(payload, 1)                         // one column
	payload = appendU32(payload, 0)                         // user type
	payload = appendU16(payload, 0x0001)                    // nullable
	payload = append(payload, 0xe7)                         // NVARCHAR
	payload = appendU16(payload, 8000)                      // max bytes
	payload = append(payload, 0x09, 0x04, 0xd0, 0x00, 0x34) // Latin1_General collation
	payload = append(payload, bVarChar(column)...)
	for _, row := range rows {
		data := encodeUCS2(row)
		if len(data) > 8000 {
			data = data[:8000]
		}
		payload = append(payload, 0xd1)
		payload = appendU16(payload, uint16(len(data)))
		payload = append(payload, data...)
	}
	return appendDone(payload, 0x0010, uint64(len(rows))) // DONE_COUNT
}

func errorResponse(number uint32, message string) []byte {
	msg := encodeUCS2(message)
	body := appendU32(nil, number)
	body = append(body, 1, 14)
	body = appendU16(body, uint16(len([]rune(message))))
	body = append(body, msg...)
	body = append(body, bVarChar("SQLSERVER01")...)
	body = append(body, bVarChar("")...)
	body = appendU32(body, 1)
	payload := []byte{0xaa}
	payload = appendU16(payload, uint16(len(body)))
	payload = append(payload, body...)
	return appendDone(payload, 0x0002, 0) // DONE_ERROR
}

func parseSQLBatch(payload []byte) string {
	return strings.TrimSpace(decodeUCS2(payload))
}
