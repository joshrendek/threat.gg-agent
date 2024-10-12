package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"

	"github.com/Masterminds/semver/v3"
)

const (
	owner         = "joshrendek"
	repo          = "threat.gg-agent"
	githubAPIBase = "https://api.github.com/repos/%s/%s/releases/latest"
)

type Release struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func CheckAndUpdate(currentVersion string) error {
	ctx := context.Background()
	client := &http.Client{}

	url := fmt.Sprintf(githubAPIBase, owner, repo)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch latest release: %w", err)
	}
	defer resp.Body.Close()

	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return fmt.Errorf("failed to decode release info: %w", err)
	}

	latestVersion, err := semver.NewVersion(strings.TrimPrefix(release.TagName, "v"))
	if err != nil {
		return fmt.Errorf("invalid version format: %w", err)
	}

	currentSemver, err := semver.NewVersion(strings.TrimPrefix(currentVersion, "v"))
	if err != nil {
		return fmt.Errorf("invalid current version format: %w", err)
	}

	if latestVersion.GreaterThan(currentSemver) {
		fmt.Printf("New version available: %s (current: %s)\n", latestVersion, currentSemver)
		return downloadAndReplace(release)
	}

	fmt.Println("Already running the latest version.")
	return nil
}

func downloadAndReplace(release Release) error {
	assetName := fmt.Sprintf("%s_%s_%s", repo, runtime.GOOS, runtime.GOARCH)
	var downloadURL string

	for _, asset := range release.Assets {
		if strings.HasPrefix(asset.Name, assetName) {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}

	if downloadURL == "" {
		return fmt.Errorf("no suitable asset found for this system")
	}

	resp, err := http.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("failed to download new version: %w", err)
	}
	defer resp.Body.Close()

	tempFile, err := os.CreateTemp("", "threat.gg-agent-*")
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

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current executable path: %w", err)
	}

	if err := os.Rename(tempFile.Name(), execPath); err != nil {
		return fmt.Errorf("failed to replace current executable: %w", err)
	}

	fmt.Println("Successfully updated to the latest version. Please restart the application.")
	return nil
}
