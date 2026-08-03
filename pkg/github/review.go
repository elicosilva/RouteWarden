package github

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/routewarden/routewarden/pkg/output"
)

// ReviewCommentRequest is the payload for a single inline PR review
// comment. It intentionally has no `position` field: rule R1 requires the
// modern `line`+`side` addressing, which stays correct even when unrelated
// hunks in the diff shift — the legacy `position` field is a raw offset
// into the diff text and breaks silently when that happens.
type ReviewCommentRequest struct {
	Body     string `json:"body"`
	CommitID string `json:"commit_id"`
	Path     string `json:"path"`
	Line     int    `json:"line"`
	Side     string `json:"side"` // always "RIGHT": comment on the new code
}

// PostReviewComment posts a single inline comment on a pull request. This
// is RouteWarden's only write operation against GitHub — everything else
// is read-only (rule R7) — and it never merges, approves, or requests
// changes on anything (rule R1: human-in-the-loop always; the human reads
// this comment and decides).
func (f *Fetcher) PostReviewComment(owner, repo string, pullNumber int, commitID, path string, line int, body string) error {
	base := f.APIBase
	if base == "" {
		base = defaultAPIBase
	}

	reqBody := ReviewCommentRequest{
		Body:     body,
		CommitID: commitID,
		Path:     path,
		Line:     line,
		Side:     "RIGHT",
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("github: encode review comment: %w", err)
	}

	endpoint := fmt.Sprintf("%s/repos/%s/%s/pulls/%d/comments",
		base, url.PathEscape(owner), url.PathEscape(repo), pullNumber)

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("github: build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+f.Token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	client := f.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("github: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("github: read response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("github: unexpected status %d posting review comment on %s/%s PR #%d: %s",
			resp.StatusCode, owner, repo, pullNumber, string(respBody))
	}

	return nil
}

// FormatFindingComment renders an output.Finding as Markdown for a GitHub
// PR review comment body (rule R6: every finding must be human-auditable —
// this is the text the human actually reads to decide what to do).
func FormatFindingComment(f output.Finding) string {
	return fmt.Sprintf(
		"**RouteWarden — %s risk** (`%s`)\n\n%s\n\n_Confidence: %.0f%%_",
		f.Risk, f.CWE, f.Reason, f.Confidence*100,
	)
}
