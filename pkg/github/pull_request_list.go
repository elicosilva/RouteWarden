package github

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// PullRequestSummary is the minimal info needed to dry-run scan a
// historical pull request: which PR, and the commit to fetch file content
// at.
type PullRequestSummary struct {
	Number   int
	HeadSHA  string
	MergedAt string // RFC3339 timestamp
}

type prSummaryResponse struct {
	Number   int     `json:"number"`
	MergedAt *string `json:"merged_at"`
	Head     struct {
		SHA string `json:"sha"`
	} `json:"head"`
}

// ListRecentMergedPullRequests returns up to `limit` recently-updated,
// merged pull requests for a repository, paginating as needed. Only merged
// PRs are returned — a closed-but-not-merged PR was rejected, so it isn't
// representative of code the project actually accepted (important for a
// benchmark: we want signal from real accepted code, not abandoned
// proposals).
func (f *Fetcher) ListRecentMergedPullRequests(owner, repo string, limit int) ([]PullRequestSummary, error) {
	base := f.APIBase
	if base == "" {
		base = defaultAPIBase
	}

	client := f.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	var results []PullRequestSummary

	for page := 1; len(results) < limit && page <= 20; page++ {
		endpoint := fmt.Sprintf("%s/repos/%s/%s/pulls?state=closed&sort=updated&direction=desc&per_page=100&page=%d",
			base, url.PathEscape(owner), url.PathEscape(repo), page)

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
			return nil, fmt.Errorf("github: unexpected status %d listing PRs for %s/%s: %s",
				resp.StatusCode, owner, repo, string(body))
		}

		var page []prSummaryResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("github: decode PR list response: %w", err)
		}

		if len(page) == 0 {
			break // no more pages
		}

		for _, pr := range page {
			if pr.MergedAt == nil {
				continue // closed without merging: not accepted code
			}
			results = append(results, PullRequestSummary{
				Number:   pr.Number,
				HeadSHA:  pr.Head.SHA,
				MergedAt: *pr.MergedAt,
			})
			if len(results) >= limit {
				break
			}
		}
	}

	return results, nil
}
