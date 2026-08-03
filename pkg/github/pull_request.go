package github

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// PullRequestFile is one entry from GitHub's Pull Request Files API:
// https://docs.github.com/en/rest/pulls/pulls#list-pull-requests-files
//
// Patch is the unified diff *hunks* for this file only — GitHub does not
// include the "diff --git"/"---"/"+++" header lines that a raw `git diff`
// would have, so UnifiedDiff() synthesizes them before handing the text to
// pkg/diff.ParseAddedLines.
type PullRequestFile struct {
	Filename         string
	PreviousFilename string // only set when Status == "renamed"
	Status           string // "added", "modified", "removed", "renamed"
	Patch            string
}

// UnifiedDiff reconstructs a full unified diff for this file, suitable for
// pkg/diff.ParseAddedLines. Returns ok=false for files with nothing to
// parse: removed files (nothing new to scan) and files with no Patch at
// all (binary files, or renames with no content change).
func (f PullRequestFile) UnifiedDiff() (diffText string, ok bool) {
	if f.Status == "removed" || f.Patch == "" {
		return "", false
	}

	oldPath := f.Filename
	if f.PreviousFilename != "" {
		oldPath = f.PreviousFilename
	}

	oldHeader := fmt.Sprintf("--- a/%s\n", oldPath)
	if f.Status == "added" {
		oldHeader = "--- /dev/null\n"
	}

	diffText = fmt.Sprintf(
		"diff --git a/%s b/%s\n%s+++ b/%s\n%s\n",
		oldPath, f.Filename, oldHeader, f.Filename, f.Patch,
	)
	return diffText, true
}

type prFileResponse struct {
	Filename         string `json:"filename"`
	PreviousFilename string `json:"previous_filename"`
	Status           string `json:"status"`
	Patch            string `json:"patch"`
}

// FetchPullRequestFiles retrieves every changed file in a pull request via
// the Files API, paginating as needed (rule R5: this — not a full clone —
// is how RouteWarden learns which files a PR touched).
func (f *Fetcher) FetchPullRequestFiles(owner, repo string, number int) ([]PullRequestFile, error) {
	base := f.APIBase
	if base == "" {
		base = defaultAPIBase
	}

	client := f.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	var allFiles []PullRequestFile

	for page := 1; page <= 20; page++ {
		endpoint := fmt.Sprintf("%s/repos/%s/%s/pulls/%d/files?per_page=100&page=%d",
			base, url.PathEscape(owner), url.PathEscape(repo), number, page)

		req, err := http.NewRequest(http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("github: build request: %w", err)
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("Authorization", "Bearer "+f.Token)
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("github: request failed: %w", err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("github: read response: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("github: unexpected status %d fetching %s/%s PR #%d files: %s",
				resp.StatusCode, owner, repo, number, string(body))
		}

		var pageFiles []prFileResponse
		if err := json.Unmarshal(body, &pageFiles); err != nil {
			return nil, fmt.Errorf("github: decode PR files response: %w", err)
		}

		if len(pageFiles) == 0 {
			break
		}

		for _, pf := range pageFiles {
			allFiles = append(allFiles, PullRequestFile{
				Filename:         pf.Filename,
				PreviousFilename: pf.PreviousFilename,
				Status:           pf.Status,
				Patch:            pf.Patch,
			})
		}

		if len(pageFiles) < 100 {
			break // last page
		}
	}

	return allFiles, nil
}
