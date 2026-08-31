package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	owner         = "joshrendek"
	repo          = "threat.gg-agent"
	githubAPIBase = "https://api.github.com/repos/%s/%s/releases/latest"
	binaryName    = "honeypot"
)

type Release struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func CheckAndUpdate(currentVersion string) (bool, error) {
	if os.Getenv("SKIP_UPDATE") != "" {
		fmt.Println("Skipping update check.")
		return false, nil
	}
	ctx := context.Background()
	client := &http.Client{}

	url := fmt.Sprintf(githubAPIBase, owner, repo)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to fetch latest release: %w", err)
	}
	defer resp.Body.Close()

	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return false, fmt.Errorf("failed to decode release info: %w", err)
	}

	latestVersion := strings.Split(release.TagName, ".")

	if len(latestVersion) != 2 {
		return false, fmt.Errorf("invalid version format returned from API")
	}

	if err != nil {
		return false, fmt.Errorf("invalid version format: %w", err)
	}

	currentVer := strings.Split(currentVersion, ".")
	if err != nil {
		return false, fmt.Errorf("invalid current version format: %w", err)
	}

	// Check calver date first, then build number.
	if latestVersion[0] > currentVer[0] || latestVersion[1] > currentVer[1] {
		fmt.Printf("New version available: %s (current: %s)\n", release.TagName, currentVersion)
		if err := downloadAndReplace(release); err != nil {
			// Report NOT-updated on failure. This previously returned
			// `true, downloadAndReplace(release)`, which claimed success even
			// when the replace failed -- and main.go exits the process when
			// updated is true. A failing update therefore killed the agent
			// every 15 minutes, systemd restarted it 10 seconds later, and the
			// node sat in a crash loop with its honeypot ports flapping while
			// systemctl still reported the unit active.
			//
			// A failed update must leave the agent running on the old binary.
			// That is a degraded state worth an alert, never a reason to stop
			// serving.
			return false, err
		}
		return true, nil
	}

	fmt.Println("Already running the latest version.")
	return false, nil
}

func removeNullBytes(data []byte) []byte {
	// Create a new slice to hold the result without null bytes
	result := make([]byte, 0, len(data))

	// Loop through the original slice
	for _, b := range data {
		// Only append non-null bytes to the result
		if b != 0 {
			result = append(result, b)
		}
	}
	return result
}

func downloadAndReplace(release Release) error {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return err
	}

	assetName := fmt.Sprintf("%s_%s", binaryName, string(removeNullBytes(uts.Machine[:])))
	var downloadURL string

	for _, asset := range release.Assets {
		if strings.HasPrefix(asset.Name, assetName) {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}

	if downloadURL == "" {
		return fmt.Errorf("no suitable asset found for this system: %s", assetName)
	}

	resp, err := http.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("failed to download new version: %w", err)
	}
	defer resp.Body.Close()

	// Stage the download in the SAME DIRECTORY as the binary we are replacing.
	//
	// os.Rename cannot move a file across filesystems. Using os.CreateTemp("")
	// puts the download in $TMPDIR (/tmp by default), and on any host where
	// /tmp is a separate mount -- tmpfs on the DigitalOcean ICS nodes, for
	// instance -- the rename below fails with EXDEV and the update can never
	// succeed. Staging beside the target makes same-filesystem a property of
	// the code rather than a property of the host's mount layout.
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current executable path: %w", err)
	}
	tempFile, err := os.CreateTemp(filepath.Dir(execPath), ".threat.gg-agent-update-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tempFile.Name())

	if _, err := io.Copy(tempFile, resp.Body); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err := os.Chmod(tempFile.Name(), 0755); err != nil {
		return fmt.Errorf("failed to set executable permissions: %w", err)
	}

	if err := os.Rename(tempFile.Name(), execPath); err != nil {
		return fmt.Errorf("failed to replace current executable: %w", err)
	}

	fmt.Println("Successfully updated to the latest version. Honeypot is restarting.")
	// execute systemctl restart honeypot and print the output
	cmd := exec.Command("systemctl", "restart", "honeypot")
	out, ctlErr := cmd.CombinedOutput()
	if ctlErr != nil {
		return fmt.Errorf("failed to restart honeypot: %w", ctlErr)
	}
	fmt.Println(string(out))

	return nil
}
