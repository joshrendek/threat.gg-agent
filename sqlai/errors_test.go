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
	}
	require.Equal(t, ErrorMapping{"42P01", 208, 16, 1}, Errors["undefined_table"])
	require.Equal(t, ErrorMapping{"42601", 102, 15, 1}, Errors["syntax_error"])
	require.Equal(t, ErrorMapping{"42883", 2812, 16, 62}, Errors["undefined_procedure"])
}
