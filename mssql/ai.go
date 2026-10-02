package mssql

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/joshrendek/threat.gg-agent/sqlai"
)

// mssqlAIResponse encodes a generated reply as a TDS response payload, or
// returns nil when anything in it cannot be encoded faithfully, in which case
// the caller answers with the legacy path.
func mssqlAIResponse(rs *proto.ResultSet) []byte {
	if rs == nil {
		return nil
	}
	if e := rs.GetError(); e != nil {
		m, ok := sqlai.Errors[e.GetCode()]
		msg := sqlai.Clean(e.GetMessage(), false)
		if !ok || msg == "" || utf8.RuneCountInString(msg) > maxErrorMessageRunes {
			return nil
		}
		return errorResponseWith(m.MSSQLNumber, m.MSSQLState, m.MSSQLClass, msg)
	}
	if len(rs.GetColumns()) == 0 {
		if len(rs.GetRows()) > 0 {
			return nil
		}
		if n, ok := tagCount(rs.GetCommandTag()); ok {
			return appendDone(nil, doneCount, n)
		}
		return appendDone(nil, 0, 0)
	}
	payload, ok := tdsResultSet(rs.GetColumns(), rs.GetRows())
	if !ok || len(payload) > maxMessageSize {
		return nil
	}
	return payload
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
