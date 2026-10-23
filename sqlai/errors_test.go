package sqlai

import (
	"regexp"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

// The server pins the same literal (internal/ai/validate/resultset_test.go
// TestSQLListsArePinned). Change both repos together.
func TestErrorCodesMatchServerAllowlist(t *testing.T) {
	codes := make([]string, 0, len(Errors))
	for c := range Errors {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	require.Equal(t, []string{"division_by_zero", "duplicate_database", "duplicate_object", "duplicate_table", "insufficient_privilege", "invalid_text_representation", "syntax_error", "undefined_column", "undefined_database", "undefined_function", "undefined_object", "undefined_procedure", "undefined_table"}, codes)
}

func TestErrorTableValues(t *testing.T) {
	state := regexp.MustCompile(`^[0-9A-Z]{5}$`)
	for code, m := range Errors {
		require.Regexp(t, state, m.SQLState, code)
		require.NotZero(t, m.MSSQLNumber, code)
		require.GreaterOrEqual(t, m.MSSQLClass, byte(11), code)
		require.LessOrEqual(t, m.MSSQLClass, byte(16), code)
		require.NotZero(t, m.MSSQLState, code)
		require.Regexp(t, state, m.MySQLState, code)
		require.GreaterOrEqual(t, m.MySQLNumber, uint16(1000), code) // server errors start at 1000
	}
	require.Equal(t, ErrorMapping{"42P01", 208, 16, 1, 1146, "42S02"}, Errors["undefined_table"])
	require.Equal(t, ErrorMapping{"42601", 102, 15, 1, 1064, "42000"}, Errors["syntax_error"])
	require.Equal(t, ErrorMapping{"42883", 2812, 16, 62, 1305, "42000"}, Errors["undefined_procedure"])
}

// Every condition goes out as a real MySQL 8.0 error: the number the server
// itself raises for that condition, with that number's own SQLSTATE. The mysql
// client prints both ("ERROR 1146 (42S02): ..."), so the pair must agree.
func TestMySQLErrorTable(t *testing.T) {
	want := map[string]struct {
		number uint16
		state  string
	}{
		"division_by_zero":            {1365, "22012"}, // ER_DIVISION_BY_ZERO
		"duplicate_database":          {1007, "HY000"}, // ER_DB_CREATE_EXISTS
		"duplicate_object":            {1396, "HY000"}, // ER_CANNOT_USER: CREATE USER/ROLE that exists
		"duplicate_table":             {1050, "42S01"}, // ER_TABLE_EXISTS_ERROR
		"insufficient_privilege":      {1227, "42000"}, // ER_SPECIFIC_ACCESS_DENIED_ERROR
		"invalid_text_representation": {1366, "HY000"}, // ER_TRUNCATED_WRONG_VALUE_FOR_FIELD
		"syntax_error":                {1064, "42000"}, // ER_PARSE_ERROR
		"undefined_column":            {1054, "42S22"}, // ER_BAD_FIELD_ERROR
		"undefined_database":          {1049, "42000"}, // ER_BAD_DB_ERROR
		"undefined_function":          {1305, "42000"}, // ER_SP_DOES_NOT_EXIST: FUNCTION x does not exist
		"undefined_object":            {1396, "HY000"}, // ER_CANNOT_USER: DROP USER/ROLE that does not exist
		"undefined_procedure":         {1305, "42000"}, // ER_SP_DOES_NOT_EXIST: PROCEDURE x does not exist
		"undefined_table":             {1146, "42S02"}, // ER_NO_SUCH_TABLE
	}
	require.Len(t, Errors, len(want))
	for code, m := range Errors {
		w, ok := want[code]
		require.True(t, ok, code)
		require.Equal(t, w.number, m.MySQLNumber, code)
		require.Equal(t, w.state, m.MySQLState, code)
	}
}
