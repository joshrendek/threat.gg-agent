package mysql

import (
	"io"
	"strings"
)

// MySQL COM_* command bytes
const (
	comQuit     byte = 0x01
	comInitDB   byte = 0x02
	comQuery    byte = 0x03
	comPing     byte = 0x0E
	comStatistics byte = 0x09
)

// queryResponse defines a fake result set for a known query.
type queryResponse struct {
	columns []columnDef
	rows    [][]string
}

// Fake query responses for common enumeration queries.
var queryResponses map[string]queryResponse

func init() {
	vc := columnDef{Name: "@@version_comment", ColType: 0xFD, MaxLen: 255}
	v := columnDef{Name: "@@version", ColType: 0xFD, MaxLen: 255}
	db := columnDef{Name: "Database", ColType: 0xFD, MaxLen: 255}
	tb := columnDef{Name: "Tables_in_production", ColType: 0xFD, MaxLen: 255}
	vn := columnDef{Name: "Variable_name", ColType: 0xFD, MaxLen: 255}
	vv := columnDef{Name: "Value", ColType: 0xFD, MaxLen: 255}

	queryResponses = map[string]queryResponse{
		"select @@version_comment": {
			columns: []columnDef{vc},
			rows:    [][]string{{"Ubuntu"}},
		},
		"select @@version": {
			columns: []columnDef{v},
			rows:    [][]string{{"8.0.35-0ubuntu0.24.04.1"}},
		},
		"show databases": {
			columns: []columnDef{db},
			rows: [][]string{
				{"information_schema"},
				{"mysql"},
				{"performance_schema"},
				{"sys"},
				{"production"},
				{"customers"},
			},
		},
		"show tables": {
			columns: []columnDef{tb},
			rows: [][]string{
				{"users"},
				{"orders"},
				{"payments"},
				{"sessions"},
				{"api_keys"},
				{"audit_log"},
			},
		},
		"select database()": {
			columns: []columnDef{{Name: "database()", ColType: 0xFD, MaxLen: 255}},
			rows:    [][]string{{"production"}},
		},
		"select user()": {
			columns: []columnDef{{Name: "user()", ColType: 0xFD, MaxLen: 255}},
			rows:    [][]string{{"root@localhost"}},
		},
		"select current_user()": {
			columns: []columnDef{{Name: "current_user()", ColType: 0xFD, MaxLen: 255}},
			rows:    [][]string{{"root@%"}},
		},
		"select @@hostname": {
			columns: []columnDef{{Name: "@@hostname", ColType: 0xFD, MaxLen: 255}},
			rows:    [][]string{{"db-prod-01"}},
		},
		"select @@datadir": {
			columns: []columnDef{{Name: "@@datadir", ColType: 0xFD, MaxLen: 255}},
			rows:    [][]string{{"/var/lib/mysql/"}},
		},
		"show variables like 'version'": {
			columns: []columnDef{vn, vv},
			rows:    [][]string{{"version", "8.0.35-0ubuntu0.24.04.1"}},
		},
		"show variables like 'datadir'": {
			columns: []columnDef{vn, vv},
			rows:    [][]string{{"datadir", "/var/lib/mysql/"}},
		},
		"show variables like 'secure_file_priv'": {
			columns: []columnDef{vn, vv},
			rows:    [][]string{{"secure_file_priv", ""}},
		},
	}
}

// handleComQuery dispatches a SQL query and writes a fake response.
func handleComQuery(w io.Writer, seqID uint8, query string) (uint8, error) {
	normalized := strings.ToLower(strings.TrimSpace(query))

	// Check for exact match in known queries
	if resp, ok := queryResponses[normalized]; ok {
		return writeResultSet(w, seqID, resp.columns, resp.rows)
	}

	// Pattern matching for common query prefixes
	switch {
	case strings.HasPrefix(normalized, "select"):
		// Unknown SELECT: return empty result set
		col := columnDef{Name: "result", ColType: 0xFD, MaxLen: 255}
		return writeResultSet(w, seqID, []columnDef{col}, nil)

	case strings.HasPrefix(normalized, "show"):
		// Unknown SHOW: return empty result set
		col := columnDef{Name: "result", ColType: 0xFD, MaxLen: 255}
		return writeResultSet(w, seqID, []columnDef{col}, nil)

	case strings.HasPrefix(normalized, "insert") ||
		strings.HasPrefix(normalized, "update") ||
		strings.HasPrefix(normalized, "delete") ||
		strings.HasPrefix(normalized, "replace"):
		// DML: return OK with affected_rows=1
		err := writeOKPacket(w, seqID, 1, 0)
		return seqID + 1, err

	case strings.HasPrefix(normalized, "create") ||
		strings.HasPrefix(normalized, "drop") ||
		strings.HasPrefix(normalized, "alter") ||
		strings.HasPrefix(normalized, "truncate"):
		// DDL: return OK
		err := writeOKPacket(w, seqID, 0, 0)
		return seqID + 1, err

	case strings.HasPrefix(normalized, "set") ||
		strings.HasPrefix(normalized, "use"):
		// Session commands: return OK
		err := writeOKPacket(w, seqID, 0, 0)
		return seqID + 1, err

	default:
		// Unknown: return OK
		err := writeOKPacket(w, seqID, 0, 0)
		return seqID + 1, err
	}
}

// handleComPing responds to COM_PING.
func handleComPing(w io.Writer, seqID uint8) error {
	return writeOKPacket(w, seqID, 0, 0)
}

// handleComInitDB responds to COM_INIT_DB (USE database).
func handleComInitDB(w io.Writer, seqID uint8) error {
	return writeOKPacket(w, seqID, 0, 0)
}

// handleComStatistics responds to COM_STATISTICS.
func handleComStatistics(w io.Writer, seqID uint8) error {
	stats := "Uptime: 1847293  Threads: 3  Questions: 14829  Slow queries: 0  Opens: 412  Flush tables: 3  Open tables: 331  Queries per second avg: 0.008"
	return writePacket(w, seqID, []byte(stats))
}
