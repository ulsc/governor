package update

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"governor/internal/version"
)

// Result holds the outcome of an update check.
type Result struct {
	NewVersion string // e.g. "v0.2.0", empty if no update available
}

// githubRelease is the minimal JSON shape returned by the GitHub releases API.
type githubRelease struct {
	TagName string `json:"tag_name"`
}

// endpoint is the GitHub API URL for the latest release. Exported as a variable
// so tests can override it.
var endpoint = "https://api.github.com/repos/ulsc/governor/releases/latest"

// CheckAsync starts a background update check and returns a buffered channel
// that will receive exactly one Result. If the current version is "dev", no
// HTTP call is made and an empty Result is sent immediately.
func CheckAsync() <-chan Result {
	ch := make(chan Result, 1)
	if version.Version == "dev" {
		ch <- Result{}
		return ch
	}
	go func() {
		ch <- checkURL(endpoint, version.Version)
	}()
	return ch
}

// checkURL performs a synchronous HTTP GET against the given endpoint and
// compares the returned tag against current. Any error silently produces an
// empty Result.
func checkURL(url, current string) Result {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return Result{}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Result{}
	}

	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return Result{}
	}

	tag := rel.TagName
	if tag == "" {
		return Result{}
	}
	if tag > current {
		return Result{NewVersion: tag}
	}
	return Result{}
}

// PrintNotice prints an update notice to stderr if a newer version is
// available. Returns true if a notice was printed.
func PrintNotice(r Result) bool {
	if r.NewVersion == "" {
		return false
	}
	fmt.Fprintf(os.Stderr, "\nA new version of governor is available: %s (current: %s)\n", r.NewVersion, version.Version)
	fmt.Fprintln(os.Stderr, "Update: curl -fsSL https://governor.sh/install.sh | bash")
	return true
}
