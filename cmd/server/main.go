// Command server runs the RouteWarden GitHub webhook receiver: it listens
// for pull_request events and delegates to pkg/pipeline for the actual
// scan, then posts one inline PR comment per finding (rule R1:
// human-in-the-loop, never auto-merge).
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/routewarden/routewarden/pkg/github"
	"github.com/routewarden/routewarden/pkg/pipeline"
	"github.com/routewarden/routewarden/pkg/scanner/rules"
)

func main() {
	token := requireEnv("GITHUB_TOKEN")
	secret := requireEnv("WEBHOOK_SECRET")
	rulesPath := envOrDefault("RULES_YAML_PATH", "rules.yaml")
	port := envOrDefault("PORT", "8080")

	catalog, err := rules.LoadCatalog(rulesPath)
	if err != nil {
		log.Fatalf("routewarden: failed to load rules catalog: %v", err)
	}

	fetcher := github.NewFetcher(token)

	onEvent := func(event *github.PullRequestEvent) error {
		return scanPullRequest(fetcher, catalog, event)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", github.WebhookHandler(secret, onEvent))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	addr := ":" + port
	log.Printf("routewarden: listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("routewarden: server error: %v", err)
	}
}

// scanPullRequest runs the read-only pipeline (pkg/pipeline) and then
// posts one comment per finding — the only place in the whole codebase
// that writes to GitHub.
func scanPullRequest(fetcher *github.Fetcher, catalog *rules.Catalog, event *github.PullRequestEvent) error {
	log.Printf("routewarden: scanning %s/%s PR #%d (%s) at %s",
		event.Owner, event.Repo, event.Number, event.Action, event.HeadSHA)

	results, err := pipeline.ScanPullRequestFiles(fetcher, catalog, event.Owner, event.Repo, event.Number, event.HeadSHA)
	if err != nil {
		return err
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
				event.Owner, event.Repo, event.Number,
				event.HeadSHA, finding.File, finding.Line, comment,
			); err != nil {
				log.Printf("routewarden: failed to post comment on %s:%d: %v", finding.File, finding.Line, err)
				continue
			}
			totalFindings++
		}
	}

	log.Printf("routewarden: scan complete for %s/%s PR #%d — %d finding(s) posted",
		event.Owner, event.Repo, event.Number, totalFindings)

	return nil
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
