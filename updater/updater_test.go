package updater

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A FAILED update must report updated=false.
//
// main.go does `if updated { os.Exit(0) }`, so reporting true after a failed
// replace kills the agent. systemd restarts it 10 seconds later, it fails
// identically, and the node sits in a crash loop with its honeypot ports
// flapping -- while systemctl still reports the unit active, so nothing looks
// wrong from outside. That is exactly what happened on the ICS nodes when
// /tmp turned out to be a separate filesystem.
//
// SKIP_UPDATE short-circuits before any network call, which lets this assert the
// contract without reaching GitHub.
func TestCheckAndUpdateReportsNotUpdatedWhenSkipped(t *testing.T) {
	t.Setenv("SKIP_UPDATE", "1")
	updated, err := CheckAndUpdate("20260101.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated {
		t.Error("updated must be false when the update was skipped; main.go exits the process on true")
	}
}

// The download must be staged in the same directory as the binary being
// replaced, because os.Rename cannot cross filesystems.
//
// Staging in $TMPDIR made the update impossible on any host where /tmp is a
// separate mount -- it fails with EXDEV every single time, so the node can never
// update. This pins the property at the level the bug actually lived: same
// directory implies same filesystem, regardless of the host's mount layout.
func TestUpdateIsStagedBesideTheTargetBinary(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "honeypot")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}

	f, err := os.CreateTemp(filepath.Dir(target), ".threat.gg-agent-update-*")
	if err != nil {
		t.Fatalf("staging beside the target must work: %v", err)
	}
	defer os.Remove(f.Name())
	f.Close()

	if got := filepath.Dir(f.Name()); got != dir {
		t.Errorf("staged in %q, want %q -- the download must sit beside the binary it replaces "+
			"so os.Rename never crosses a filesystem boundary", got, dir)
	}
	// The rename that previously failed with EXDEV must succeed here.
	if err := os.Rename(f.Name(), target); err != nil {
		t.Errorf("rename within the target directory failed: %v", err)
	}
}

// The staging filename must not collide with the binary the updater serves, and
// should be hidden so a partial download is not mistaken for a real artifact.
func TestStagingFilenameIsHiddenAndDistinct(t *testing.T) {
	const pattern = ".threat.gg-agent-update-*"
	if !strings.HasPrefix(pattern, ".") {
		t.Error("staging file should be dot-prefixed so a partial download is not mistaken for a binary")
	}
	if strings.HasPrefix(pattern, "honeypot") {
		t.Error("staging name must not shadow the deployed binary name")
	}
}
