// Command action runs RouteWarden inside a GitHub Actions workflow step.
// Unlike cmd/server (which listens for webhooks long-running), this reads
// the event payload GitHub Actions already provides on disk, runs one
// scan, posts comments, and exits. Same pipeline, same rules, different
// trigger — no server to host, no webhook secret to manage.
package main

import (
	"encoding/json"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/routewarden/routewarden/pkg/github"
	"github.com/routewarden/routewarden/pkg/pipeline"
	"github.com/routewarden/routewarden/pkg/scanner/rules"
)

// eventPayload is the subset of the GitHub Actions pull_request event JSON
// (at GITHUB_EVENT_PATH) that we actually need.
type eventPayload struct {
	PullRequest struct {
		Number int `json:"number"`
		Head   struct {
			SHA string `json:"sha"`
		} `json:"head"`
	} `json:"pull_request"`
}

func main() {
	// GitHub Actions turns a `with: github-token: ...` input into the env
	// var INPUT_GITHUB_TOKEN. We also accept a plain GITHUB_TOKEN so the
	// binary works the same way outside Actions (e.g. local testing).
	token := os.Getenv("INPUT_GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		log.Fatalf("routewarden: no token found — set 'with: github-token' in the workflow step")
	}

	repoFull := requireEnv("GITHUB_REPOSITORY") // "owner/repo"
	eventPath := requireEnv("GITHUB_EVENT_PATH")
	rulesPath := envOrDefault("INPUT_RULES_PATH", "rules.yaml")

	owner, repo, ok := strings.Cut(repoFull, "/")
	if !ok {
		log.Fatalf("routewarden: unexpected GITHUB_REPOSITORY value %q", repoFull)
	}

	raw, err := os.ReadFile(eventPath)
	if err != nil {
		log.Fatalf("routewarden: failed to read event payload: %v", err)
	}

	var event eventPayload
	if err := json.Unmarshal(raw, &event); err != nil {
		log.Fatalf("routewarden: failed to parse event payload: %v", err)
	}
	if event.PullRequest.Number == 0 {
		log.Fatalf("routewarden: this action only runs on pull_request events (no PR number found in payload)")
	}

	catalog, err := rules.LoadCatalog(rulesPath)
	if err != nil {
		log.Fatalf("routewarden: failed to load rules catalog (%s): %v", rulesPath, err)
	}

	fetcher := github.NewFetcher(token)

	log.Printf("routewarden: scanning %s/%s PR #%d at %s",
		owner, repo, event.PullRequest.Number, event.PullRequest.Head.SHA)

	results, err := pipeline.ScanPullRequestFiles(
		fetcher, catalog, owner, repo, event.PullRequest.Number, event.PullRequest.Head.SHA,
	)
	if err != nil {
		log.Fatalf("routewarden: scan failed: %v", err)
	}

	totalFindings := 0
	for _, result := range results {
		if result.Skipped != "" {
			log.Printf("routewarden: skipping %s: %s", result.Filename, result.Skipped)
			continue
		}
		for _, finding := range result.Findings {
			comment := github.FormatFindingComment(finding)
			if err := fetcher.PostReviewComment(
				owner, repo, event.PullRequest.Number,
				event.PullRequest.Head.SHA, finding.File, finding.Line, comment,
			); err != nil {
				log.Printf("routewarden: failed to post comment on %s:%d: %v", finding.File, finding.Line, err)
				continue
			}
			totalFindings++
		}
	}

	log.Printf("routewarden: scan complete — %d finding(s) posted", totalFindings)

	// Surface a step output so workflows can branch on it (e.g. fail CI
	// only if findings > 0, without RouteWarden itself ever blocking).
	if out := os.Getenv("GITHUB_OUTPUT"); out != "" {
		f, err := os.OpenFile(out, os.O_APPEND|os.O_WRONLY, 0644)
		if err == nil {
			defer f.Close()
			f.WriteString("findings-count=" + strconv.Itoa(totalFindings) + "\n")
		}
	}
}

func requireEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("routewarden: required environment variable %s is not set", key)
	}
	return v
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
