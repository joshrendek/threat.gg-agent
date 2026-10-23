package sqlai

// ErrorMapping is how one error condition goes out on each wire protocol.
type ErrorMapping struct {
	SQLState    string // Postgres SQLSTATE
	MSSQLNumber uint32
	MSSQLClass  byte // severity
	MSSQLState  byte
	MySQLNumber uint16 // MySQL 8.0 server error number
	MySQLState  string // the SQLSTATE MySQL itself pairs with MySQLNumber
}

// Errors maps the server's closed set of condition names (internal/ai/validate
// SQLErrorCodes on the server) to protocol numbers. The model only ever names
// a condition, so it cannot choose the number a client sees.
//
// MySQL has no one-to-one counterpart for some conditions; each takes the
// error MySQL 8.0 raises in the case a honeypot session most often hits:
// duplicate_object and undefined_object are ER_CANNOT_USER (1396, "Operation
// CREATE USER failed for ..." / "Operation DROP USER failed for ..."), and
// undefined_function and undefined_procedure share ER_SP_DOES_NOT_EXIST
// (1305), exactly as MySQL does.
var Errors = map[string]ErrorMapping{
	"division_by_zero":            {"22012", 8134, 16, 1, 1365, "22012"},
	"duplicate_database":          {"42P04", 1801, 16, 3, 1007, "HY000"},
	"duplicate_object":            {"42710", 15025, 16, 1, 1396, "HY000"},
	"duplicate_table":             {"42P07", 2714, 16, 6, 1050, "42S01"},
	"insufficient_privilege":      {"42501", 229, 14, 5, 1227, "42000"},
	"invalid_text_representation": {"22P02", 245, 16, 1, 1366, "HY000"},
	"syntax_error":                {"42601", 102, 15, 1, 1064, "42000"},
	"undefined_column":            {"42703", 207, 16, 1, 1054, "42S22"},
	"undefined_database":          {"3D000", 911, 16, 1, 1049, "42000"},
	"undefined_function":          {"42883", 195, 15, 10, 1305, "42000"},
	"undefined_object":            {"42704", 15151, 16, 1, 1396, "HY000"},
	"undefined_procedure":         {"42883", 2812, 16, 62, 1305, "42000"},
	"undefined_table":             {"42P01", 208, 16, 1, 1146, "42S02"},
}
