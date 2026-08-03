// Package github provides a minimal client for the GitHub REST API,
// deliberately built on net/http instead of a heavy SDK (per the locked
// stack in section 3 of the project spec).
package github

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const defaultAPIBase = "https://api.github.com"

// Fetcher retrieves file contents from GitHub via the Contents API. It only
// reads source code — never writes, and never talks to any host other than
// the GitHub API (rule R7).
type Fetcher struct {
	// Token is sent as a Bearer token. In this phase it is a Personal
	// Access Token; a later phase swaps it for a GitHub App installation
	// token without changing this struct's shape.
	Token string

	// APIBase allows overriding the API host, mainly for GitHub Enterprise
	// Server or tests. Defaults to https://api.github.com.
	APIBase string

	HTTPClient *http.Client
}

// NewFetcher creates a Fetcher with sane defaults.
func NewFetcher(token string) *Fetcher {
	return &Fetcher{
		Token:      token,
		APIBase:    defaultAPIBase,
		HTTPClient: http.DefaultClient,
	}
}

// contentsResponse mirrors the fields we need from the GitHub Contents API
// response. See:
// https://docs.github.com/en/rest/repos/contents#get-repository-content
type contentsResponse struct {
	Type     string `json:"type"`
	Encoding string `json:"encoding"`
	Content  string `json:"content"`
	Size     int    `json:"size"`
	SHA      string `json:"sha"`
}

// FetchFile retrieves the full content of a single file at a given ref
// (branch, tag, or commit SHA). This is used to get valid, complete source
// for AST parsing (rule R5) rather than trying to parse a diff hunk alone.
func (f *Fetcher) FetchFile(owner, repo, path, ref string) ([]byte, error) {
	base := f.APIBase
	if base == "" {
		base = defaultAPIBase
	}

	endpoint := fmt.Sprintf("%s/repos/%s/%s/contents/%s?ref=%s",
		base,
		url.PathEscape(owner),
		url.PathEscape(repo),
		escapePath(path),
		url.QueryEscape(ref),
	)

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("github: build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+f.Token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := f.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("github: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github: unexpected status %d fetching %s/%s@%s:%s: %s",
			resp.StatusCode, owner, repo, ref, path, string(body))
	}

	var parsed contentsResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("github: decode response: %w", err)
	}

	if parsed.Type != "file" {
		return nil, fmt.Errorf("github: %s/%s:%s is a %q, not a file", owner, repo, path, parsed.Type)
	}

	if parsed.Encoding != "base64" {
		return nil, fmt.Errorf("github: unsupported content encoding %q for %s", parsed.Encoding, path)
	}

	// GitHub's base64 payload is split across multiple lines; the standard
	// decoder handles embedded newlines fine, but we strip them defensively
	// in case that ever changes.
	decoded, err := base64.StdEncoding.DecodeString(stripNewlines(parsed.Content))
	if err != nil {
		return nil, fmt.Errorf("github: decode base64 content for %s: %w", path, err)
	}

	return decoded, nil
}

// escapePath escapes each path segment individually so that legitimate
// slashes in the file path are preserved while special characters within a
// segment are encoded.
func escapePath(path string) string {
	escaped := url.PathEscape(path)
	// url.PathEscape also escapes '/', which we need to preserve.
	return replaceAll(escaped, "%2F", "/")
}

func replaceAll(s, old, new string) string {
	result := ""
	for {
		idx := indexOf(s, old)
		if idx == -1 {
			return result + s
		}
		result += s[:idx] + new
		s = s[idx+len(old):]
	}
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func stripNewlines(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\n' && s[i] != '\r' {
			out = append(out, s[i])
		}
	}
	return string(out)
}
