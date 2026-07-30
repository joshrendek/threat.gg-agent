package promptrules

import (
	"os"
	"testing"

	"github.com/rs/zerolog"
)

// TestMain silences the package logger. Several tests deliberately drive the drop,
// refuse, panic and budget-exhaustion paths, and each of those is supposed to log --
// so leaving the logger on buries a real failure under a few hundred lines of
// expected warnings. Set PROMPTRULES_TEST_LOG=1 to see them while debugging.
func TestMain(m *testing.M) {
	if os.Getenv("PROMPTRULES_TEST_LOG") != "1" {
		logger = logger.Level(zerolog.Disabled)
	}
	os.Exit(m.Run())
}
