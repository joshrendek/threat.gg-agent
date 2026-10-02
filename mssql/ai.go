package mssql

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/joshrendek/threat.gg-agent/sqlai"
)

// mssqlAIResponse encodes a generated reply as a TDS response payload. It
// returns nil when there is no reply, and nil with a reason when the reply
// cannot be encoded faithfully; either way the caller answers with the legacy
// path. The reason never carries query or model text.
func mssqlAIResponse(rs *proto.ResultSet) (payload []byte, discarded string) {
	if rs == nil {
		return nil, ""
	}
	if e := rs.GetError(); e != nil {
		m, ok := sqlai.Errors[e.GetCode()]
		msg := sqlai.Clean(e.GetMessage(), false)
		if !ok || msg == "" || utf8.RuneCountInString(msg) > maxErrorMessageRunes {
			return nil, "error_not_mapped"
		}
		return errorResponseWith(m.MSSQLNumber, m.MSSQLState, m.MSSQLClass, msg), ""
	}
	if len(rs.GetColumns()) == 0 {
		if len(rs.GetRows()) > 0 {
			return nil, "rows_without_columns"
		}
		if n, ok := tagCount(rs.GetCommandTag()); ok {
			return appendDone(nil, doneCount, n), ""
		}
		return appendDone(nil, 0, 0), ""
	}
	payload, ok := tdsResultSet(rs.GetColumns(), rs.GetRows())
	if !ok || len(payload) > maxMessageSize {
		return nil, "result_not_encodable"
	}
	return payload, ""
}

// tagCount is the rows-affected number at the end of a command tag ("INSERT 3").
func tagCount(tag string) (uint64, bool) {
	f := strings.Fields(tag)
	if len(f) < 2 {
		return 0, false
	}
	n, err := strconv.ParseUint(f[len(f)-1], 10, 64)
	return n, err == nil
}
