package mysql

import (
	"encoding/json"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/joshrendek/threat.gg-agent/sqlai"
)

// MySQL column type bytes (include/field_types.h).
const (
	typeTiny       byte = 0x01
	typeShort      byte = 0x02
	typeLong       byte = 0x03
	typeFloat      byte = 0x04
	typeDouble     byte = 0x05
	typeTimestamp  byte = 0x07
	typeLongLong   byte = 0x08
	typeDate       byte = 0x0A
	typeDatetime   byte = 0x0C
	typeJSON       byte = 0xF5
	typeNewDecimal byte = 0xF6
	typeBlob       byte = 0xFC
	typeVarString  byte = 0xFD
)

const (
	// maxErrorMessageBytes is MYSQL_ERRMSG_SIZE-1: MySQL cuts longer messages.
	maxErrorMessageBytes = 511
	// maxColumnNameBytes is MySQL's limit on a column alias (NAME_CHAR_LEN*4 bytes).
	maxColumnNameBytes = 256
	maxAIColumns       = 64
	maxAIRows          = 1000
	// maxAIResultBytes bounds an encoded AI reply; the server caps a result set at 1 MiB
	// of JSON, so a larger encoding means something is wrong.
	maxAIResultBytes = 2 << 20
	// notFixedDec is the decimals MySQL reports for FLOAT and DOUBLE (NOT_FIXED_DEC).
	notFixedDec = 31
	// maxDecimalScale and maxDecimalPrecision are DECIMAL's limits.
	maxDecimalScale     = 30
	maxDecimalPrecision = 65
)

// mysqlType is how one canonical column type goes over the MySQL text protocol: the
// metadata a real MySQL 8.0 server sends for a table column of the type the server's
// persona names for it (persona.mysqlTypeNames). The client adds NUM_FLAG itself.
type mysqlType struct {
	id       byte
	length   uint32
	charset  uint16
	flags    uint16
	decimals byte
}

// mysqlTypes maps the server's 16 canonical column types (validate.SQLColumnTypes). The
// MySQL prompt tells the model bool and timestamptz are never used; they still map, to
// tinyint(1) and TIMESTAMP, so such a reply is not wasted.
var mysqlTypes = map[string]mysqlType{
	"bool":        {typeTiny, 1, charsetBinary, 0, 0},
	"int2":        {typeShort, 6, charsetBinary, 0, 0},
	"int4":        {typeLong, 11, charsetBinary, 0, 0},
	"int8":        {typeLongLong, 20, charsetBinary, 0, 0},
	"oid":         {typeLong, 10, charsetBinary, flagUnsigned, 0},
	"float4":      {typeFloat, 12, charsetBinary, 0, notFixedDec},
	"float8":      {typeDouble, 22, charsetBinary, 0, notFixedDec},
	"numeric":     {typeNewDecimal, 12, charsetBinary, 0, 2}, // decimal(10,2); sized from the values when there are any
	"varchar":     {typeVarString, 1020, uint16(charsetUTF8MB4), 0, 0},
	"name":        {typeVarString, 256, uint16(charsetUTF8MB4), 0, 0},
	"text":        {typeBlob, 262140, uint16(charsetUTF8MB4), flagBlob, 0},
	"json":        {typeJSON, math.MaxUint32, charsetBinary, flagBlob | flagBinary, 0},
	"jsonb":       {typeJSON, math.MaxUint32, charsetBinary, flagBlob | flagBinary, 0},
	"date":        {typeDate, 10, charsetBinary, flagBinary, 0},
	"timestamp":   {typeDatetime, 19, charsetBinary, flagBinary, 0},
	"timestamptz": {typeTimestamp, 19, charsetBinary, flagBinary, 0},
}

var (
	intRe     = regexp.MustCompile(`^-?[0-9]+$`)
	floatRe   = regexp.MustCompile(`^-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)
	decimalRe = regexp.MustCompile(`^-?([0-9]+)(?:\.([0-9]+))?$`)
	// rowsAffectedTagRe is a command tag whose count is rows affected: "INSERT 3",
	// "UPDATE 2", and Postgres's "INSERT 0 1" too.
	rowsAffectedTagRe = regexp.MustCompile(`^(?:INSERT|UPDATE|DELETE|REPLACE)(?: [0-9]+)* ([0-9]+)$`)
)

// answerQuery answers one COM_QUERY: AI first (spec §2 precedence, §15), then exactly
// the reply the honeypot sent before AI existed. The AI session state lives on sess,
// since a MySQL session is one connection.
func (h *honeypot) answerQuery(w io.Writer, seqID uint8, query string, sess *session) error {
	before := sess.ai
	start := time.Now()
	ans := sqlai.Ask(h.effectiveGenerate(), "mysql", sess.guid, query, before)
	elapsed := time.Since(start)
	sess.ai = ans.Session
	reply, discarded := mysqlAIResponse(ans.ResultSet, seqID, sess.deprecateEOF)
	if discarded != "" {
		// Billed by the server but never seen by the attacker.
		h.logger.Warn().Str("generation_id", ans.GenerationID).Str("protocol", "mysql").Str("reason", discarded).Msg("discarded AI reply")
	}
	if reply != nil {
		_, err := w.Write(reply)
		return err
	}
	// As in the postgres honeypot: once this ask took longer than a first ask may, or a
	// Live session's ask produced nothing usable, the authored lookup gets the short
	// deadline, so one query never waits the generate budget plus the full lookup.
	_, err := answerBuiltin(w, seqID, query, replyOpts{
		guid:         sess.guid,
		deprecateEOF: sess.deprecateEOF,
		degraded:     ans.Degraded || elapsed > sqlai.FirstBudget || before.State == sqlai.Live,
	})
	return err
}

// mysqlAIResponse encodes a generated reply as the packets of a COM_QUERY response,
// starting at seqID and framed for the session. It returns nil when there is no reply,
// and nil with a reason when the reply cannot be encoded faithfully; either way the
// caller answers with the legacy path. The reason never carries query or model text.
func mysqlAIResponse(rs *proto.ResultSet, seqID uint8, deprecateEOF bool) (stream []byte, discarded string) {
	if rs == nil {
		return nil, ""
	}
	if e := rs.GetError(); e != nil {
		m, ok := sqlai.Errors[e.GetCode()]
		msg := cutUTF8(sqlai.Clean(e.GetMessage(), false), maxErrorMessageBytes)
		if !ok || msg == "" {
			return nil, "error_not_mapped"
		}
		return appendPacket(nil, seqID, errPayload(m.MySQLNumber, m.MySQLState, msg)), ""
	}
	cols, rows := rs.GetColumns(), rs.GetRows()
	if len(cols) == 0 {
		if len(rows) > 0 {
			return nil, "rows_without_columns"
		}
		return appendPacket(nil, seqID, okPayload(0x00, rowsAffected(rs.GetCommandTag()), 0)), ""
	}
	defs, cells, ok := mysqlAIResult(cols, rows)
	if !ok {
		return nil, "result_not_encodable"
	}
	stream, _, ok = encodeResultSet(seqID, defs, cells, deprecateEOF)
	if !ok || len(stream) > maxAIResultBytes {
		return nil, "result_not_encodable"
	}
	return stream, ""
}

// mysqlAIResult checks a generated result set and converts it to column definitions
// and text-protocol cells (nil is NULL).
func mysqlAIResult(cols []*proto.Column, rows []*proto.Row) ([]columnDef, [][]*string, bool) {
	if len(cols) > maxAIColumns || len(rows) > maxAIRows {
		return nil, nil, false
	}
	defs := make([]columnDef, len(cols))
	types := make([]string, len(cols))
	for i, c := range cols {
		m, ok := mysqlTypes[c.GetType()]
		name := sqlai.Clean(c.GetName(), false)
		if !ok || len(name) > maxColumnNameBytes {
			return nil, nil, false
		}
		types[i] = c.GetType()
		defs[i] = columnDef{Name: name, ColType: m.id, MaxLen: m.length, Charset: m.charset, Flags: m.flags, Decimals: m.decimals}
	}
	cells := make([][]*string, len(rows))
	// Integer digits and scale per numeric column, to size it as decimal(p,s).
	intDigits, scale := make([]int, len(cols)), make([]int, len(cols))
	for r, row := range rows {
		values, nulls := row.GetValues(), row.GetNulls()
		if len(values) != len(cols) || (len(nulls) != 0 && len(nulls) != len(values)) {
			return nil, nil, false
		}
		cells[r] = make([]*string, len(values))
		for i, v := range values {
			if len(nulls) > 0 && nulls[i] {
				continue // nil is NULL
			}
			text, ok := mysqlValue(types[i], sqlai.Clean(v, true))
			if !ok {
				return nil, nil, false
			}
			if types[i] == "numeric" {
				m := decimalRe.FindStringSubmatch(text)
				intDigits[i], scale[i] = max(intDigits[i], len(m[1])), max(scale[i], len(m[2]))
			}
			cells[r][i] = &text
		}
	}
	for i := range defs {
		if types[i] != "numeric" || intDigits[i] == 0 {
			continue
		}
		s := min(scale[i], maxDecimalScale)
		p := min(max(intDigits[i]+s, 1), maxDecimalPrecision)
		length := uint32(p + 1) // sign
		if s > 0 {
			length++ // decimal point
		}
		defs[i].MaxLen, defs[i].Decimals = length, byte(s)
	}
	return defs, cells, true
}

// mysqlValue checks a non-NULL cell against its column type and returns the text MySQL
// itself would send for it. The server validates the same forms; the agent does not
// put a value on the wire it has not checked.
func mysqlValue(typ, v string) (string, bool) {
	switch typ {
	case "bool":
		switch v {
		case "true", "1":
			return "1", true
		case "false", "0":
			return "0", true
		}
		return "", false
	case "int2", "int4", "int8":
		bits := map[string]int{"int2": 16, "int4": 32, "int8": 64}[typ]
		_, err := strconv.ParseInt(v, 10, bits)
		return v, err == nil && intRe.MatchString(v)
	case "oid":
		_, err := strconv.ParseUint(v, 10, 32)
		return v, err == nil && intRe.MatchString(v)
	case "float4", "float8":
		bits := 32
		if typ == "float8" {
			bits = 64
		}
		f, err := strconv.ParseFloat(v, bits)
		return v, err == nil && floatRe.MatchString(v) && !math.IsNaN(f) && !math.IsInf(f, 0)
	case "numeric":
		return v, decimalRe.MatchString(v)
	case "date":
		return v, validTime(time.DateOnly, v)
	case "timestamp":
		return v, validTime(time.DateTime, v)
	case "timestamptz":
		// A TIMESTAMP is shown in the session time zone, which is the server's: UTC.
		t, err := time.Parse(time.RFC3339, v)
		if err != nil || t.UTC().Year() < 1 || t.UTC().Year() > 9999 {
			return "", false
		}
		return t.UTC().Format(time.DateTime), true
	case "json", "jsonb":
		return v, json.Valid([]byte(v))
	default: // varchar, name, text
		return v, true
	}
}

func validTime(layout, v string) bool {
	t, err := time.Parse(layout, v)
	return err == nil && t.Year() >= 1 && t.Year() <= 9999
}

// rowsAffected is the affected-rows count of an OK packet: the count at the end of an
// INSERT/UPDATE/DELETE/REPLACE tag, else 0 (the model tags any other statement OK).
func rowsAffected(tag string) uint64 {
	m := rowsAffectedTagRe.FindStringSubmatch(strings.TrimSpace(tag))
	if m == nil {
		return 0
	}
	n, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// cutUTF8 cuts s to at most n bytes without splitting a rune.
func cutUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
