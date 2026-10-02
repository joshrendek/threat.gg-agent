package mssql

import (
	"math"
	"strconv"
	"time"
	"unicode/utf16"

	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/joshrendek/threat.gg-agent/sqlai"
)

const (
	tdsIntN            = 0x26
	tdsBitN            = 0x68
	tdsFltN            = 0x6d
	tdsDateN           = 0x28
	tdsDateTime2N      = 0x2a
	tdsDateTimeOffsetN = 0x2b
	tdsNVarChar        = 0xe7
	tdsNVarCharMax     = 8000

	tokenColMetadata = 0x81
	tokenRow         = 0xd1
	tokenError       = 0xaa

	doneCount = 0x0010
	doneError = 0x0002

	// tdsServerName is the ServerName in every ERROR token. The server's MSSQL
	// prompt states the same @@SERVERNAME (internal/ai/prompt MSSQLServerName).
	tdsServerName = "SQLSERVER01"

	maxErrorMessageRunes = 2048
	// maxColumnNameUnits is SQL Server's sysname limit in UTF-16 units, which
	// is also what B_VARCHAR counts, so 128 non-BMP characters (256 units)
	// fall back to the legacy answer instead of being cut mid-pair.
	maxColumnNameUnits = 128
	maxOffsetMinutes   = 14 * 60 // SQL Server's datetimeoffset range
	daysFrom0001To1970 = 719162
)

// tdsType is how one canonical column type goes over TDS. size is the fixed
// value length for INTN/BITN/FLTN and unused otherwise; date/time types use
// scale 0.
type tdsType struct {
	id   byte
	size byte
}

// tdsTypes maps the server's 16 canonical column types (validate.SQLColumnTypes)
// to TDS. numeric travels as text so no precision is lost.
var tdsTypes = map[string]tdsType{
	"bool": {tdsBitN, 1}, "int2": {tdsIntN, 2}, "int4": {tdsIntN, 4}, "int8": {tdsIntN, 8}, "oid": {tdsIntN, 8},
	"float4": {tdsFltN, 4}, "float8": {tdsFltN, 8},
	"numeric": {tdsNVarChar, 0}, "text": {tdsNVarChar, 0}, "varchar": {tdsNVarChar, 0}, "name": {tdsNVarChar, 0},
	"json": {tdsNVarChar, 0}, "jsonb": {tdsNVarChar, 0},
	"date": {tdsDateN, 0}, "timestamp": {tdsDateTime2N, 0}, "timestamptz": {tdsDateTimeOffsetN, 0},
}

// days3 is days since 0001-01-01 as 3 little-endian bytes.
func days3(t time.Time) []byte {
	u := t.UTC().Unix()
	d := u / 86400
	if u%86400 < 0 {
		d--
	}
	days := d + daysFrom0001To1970
	return []byte{byte(days), byte(days >> 8), byte(days >> 16)}
}

// seconds3 is seconds since midnight (scale 0) as 3 little-endian bytes.
func seconds3(t time.Time) []byte {
	s := t.Hour()*3600 + t.Minute()*60 + t.Second()
	return []byte{byte(s), byte(s >> 8), byte(s >> 16)}
}

func appendTDSNull(dst []byte, t tdsType) []byte {
	if t.id == tdsNVarChar {
		return appendU16(dst, 0xffff)
	}
	return append(dst, 0)
}

func parseTDSTime(layout, v string) (time.Time, bool) {
	t, err := time.Parse(layout, v)
	return t, err == nil && t.UTC().Year() >= 1 && t.UTC().Year() <= 9999
}

// nvarcharBytes is v as UTF-16LE, capped at the column's 8000 bytes without
// splitting a surrogate pair.
func nvarcharBytes(v string) []byte {
	units := utf16.Encode([]rune(v))
	if len(units) > tdsNVarCharMax/2 {
		units = units[:tdsNVarCharMax/2]
		if last := units[len(units)-1]; last >= 0xd800 && last <= 0xdbff {
			units = units[:len(units)-1]
		}
	}
	b := make([]byte, 0, len(units)*2)
	for _, u := range units {
		b = appendU16(b, u)
	}
	return b
}

func appendTDSValue(dst []byte, t tdsType, v string) ([]byte, bool) {
	switch t.id {
	case tdsBitN:
		b, err := strconv.ParseBool(v)
		if err != nil {
			return dst, false
		}
		bit := byte(0)
		if b {
			bit = 1
		}
		return append(dst, 1, bit), true
	case tdsIntN:
		n, err := strconv.ParseInt(v, 10, int(t.size)*8)
		if err != nil {
			return dst, false
		}
		dst = append(dst, t.size)
		switch t.size {
		case 2:
			return appendU16(dst, uint16(int16(n))), true
		case 4:
			return appendU32(dst, uint32(int32(n))), true
		default:
			return appendU64(dst, uint64(n)), true
		}
	case tdsFltN:
		f, err := strconv.ParseFloat(v, int(t.size)*8)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return dst, false
		}
		dst = append(dst, t.size)
		if t.size == 4 {
			return appendU32(dst, math.Float32bits(float32(f))), true
		}
		return appendU64(dst, math.Float64bits(f)), true
	case tdsDateN:
		d, ok := parseTDSTime(time.DateOnly, v)
		if !ok {
			return dst, false
		}
		return append(append(dst, 3), days3(d)...), true
	case tdsDateTime2N:
		ts, ok := parseTDSTime("2006-01-02 15:04:05", v)
		if !ok {
			return dst, false
		}
		dst = append(dst, 6)
		dst = append(dst, seconds3(ts)...)
		return append(dst, days3(ts)...), true
	case tdsDateTimeOffsetN:
		ts, ok := parseTDSTime(time.RFC3339, v)
		if !ok {
			return dst, false
		}
		_, offset := ts.Zone()
		minutes := offset / 60
		if minutes < -maxOffsetMinutes || minutes > maxOffsetMinutes {
			return dst, false
		}
		u := ts.UTC()
		dst = append(dst, 8)
		dst = append(dst, seconds3(u)...)
		dst = append(dst, days3(u)...)
		return appendU16(dst, uint16(int16(minutes))), true
	default: // NVARCHAR
		data := nvarcharBytes(v)
		dst = appendU16(dst, uint16(len(data)))
		return append(dst, data...), true
	}
}

// tdsResultSet encodes COLMETADATA, ROWs and a counted DONE for a generated
// result set; ok=false when any column or value cannot be encoded, or the
// payload outgrows one TDS message.
func tdsResultSet(cols []*proto.Column, rows []*proto.Row) ([]byte, bool) {
	if len(cols) == 0 || len(cols) > 64 || len(rows) > 1000 {
		return nil, false
	}
	types := make([]tdsType, len(cols))
	payload := []byte{tokenColMetadata}
	payload = appendU16(payload, uint16(len(cols)))
	for i, c := range cols {
		t, ok := tdsTypes[c.GetType()]
		name := sqlai.Clean(c.GetName(), false)
		if !ok || len(utf16.Encode([]rune(name))) > maxColumnNameUnits {
			return nil, false
		}
		types[i] = t
		payload = appendU32(payload, 0)      // user type
		payload = appendU16(payload, 0x0001) // nullable
		payload = append(payload, t.id)
		switch t.id {
		case tdsIntN, tdsBitN, tdsFltN:
			payload = append(payload, t.size)
		case tdsDateTime2N, tdsDateTimeOffsetN:
			payload = append(payload, 0) // scale 0
		case tdsNVarChar:
			payload = appendU16(payload, tdsNVarCharMax)
			payload = append(payload, 0x09, 0x04, 0xd0, 0x00, 0x34) // Latin1_General collation
		}
		payload = append(payload, bVarChar(name)...)
	}
	for _, r := range rows {
		values, nulls := r.GetValues(), r.GetNulls()
		if len(values) != len(cols) || (len(nulls) != 0 && len(nulls) != len(values)) {
			return nil, false
		}
		payload = append(payload, tokenRow)
		for i, v := range values {
			if len(nulls) > 0 && nulls[i] {
				payload = appendTDSNull(payload, types[i])
				continue
			}
			var ok bool
			if payload, ok = appendTDSValue(payload, types[i], sqlai.Clean(v, true)); !ok {
				return nil, false
			}
		}
		if len(payload) > maxMessageSize {
			return nil, false
		}
	}
	return appendDone(payload, doneCount, uint64(len(rows))), true
}

// errorResponseWith is an ERROR token plus DONE_ERROR. The message length is
// counted in UTF-16 units, which is what TDS US_VARCHAR means.
func errorResponseWith(number uint32, state, class byte, message string) []byte {
	units := utf16.Encode([]rune(message))
	body := appendU32(nil, number)
	body = append(body, state, class)
	body = appendU16(body, uint16(len(units)))
	body = append(body, encodeUCS2(message)...)
	body = append(body, bVarChar(tdsServerName)...)
	body = append(body, bVarChar("")...)
	body = appendU32(body, 1)
	payload := []byte{tokenError}
	payload = appendU16(payload, uint16(len(body)))
	payload = append(payload, body...)
	return appendDone(payload, doneError, 0)
}
