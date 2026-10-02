package sqlai

// ErrorMapping is how one error condition goes out on each wire protocol.
type ErrorMapping struct {
	SQLState    string // Postgres SQLSTATE
	MSSQLNumber uint32
	MSSQLClass  byte // severity
	MSSQLState  byte
}

// Errors maps the server's closed set of condition names (internal/ai/validate
// SQLErrorCodes on the server) to protocol numbers. The model only ever names
// a condition, so it cannot choose the number a client sees.
var Errors = map[string]ErrorMapping{
	"division_by_zero":            {"22012", 8134, 16, 1},
	"duplicate_database":          {"42P04", 1801, 16, 3},
	"duplicate_object":            {"42710", 15025, 16, 1},
	"duplicate_table":             {"42P07", 2714, 16, 6},
	"insufficient_privilege":      {"42501", 229, 14, 5},
	"invalid_text_representation": {"22P02", 245, 16, 1},
	"syntax_error":                {"42601", 102, 15, 1},
	"undefined_column":            {"42703", 207, 16, 1},
	"undefined_database":          {"3D000", 911, 16, 1},
	"undefined_function":          {"42883", 195, 15, 10},
	"undefined_object":            {"42704", 15151, 16, 1},
	"undefined_procedure":         {"42883", 2812, 16, 62},
	"undefined_table":             {"42P01", 208, 16, 1},
}
