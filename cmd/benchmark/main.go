// Command benchmark runs RouteWarden's read-only scan pipeline against
// hundreds of real, merged pull requests from public repositories, and
// reports how often it fires and on what. It NEVER posts anything to
// GitHub — no comments, no writes of any kind (rule R7 applies here just
// as much as to the live server; a benchmark tool has no business writing
// to repos it doesn't own).
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/routewarden/routewarden/pkg/github"
	"github.com/routewarden/routewarden/pkg/pipeline"
	"github.com/routewarden/routewarden/pkg/scanner/rules"
)

type findingRow struct {
	Repo     string
	PRNumber int
	MergedAt string
	File     string
	Line     int
	Risk     string
	CWE      string
	Reason   string
}

func main() {
	reposFile := flag.String("repos-file", "benchmark/repos.yaml", "YAML file listing target repos")
	rulesFile := flag.String("rules-yaml", "rules.yaml", "auth middleware catalog")
	perRepoLimit := flag.Int("per-repo-limit", 100, "max merged PRs to scan per repo")
	delayMs := flag.Int("delay-ms", 500, "delay between PR scans in milliseconds (be polite to the GitHub API)")
	outputFile := flag.String("output", "benchmark_findings.csv", "CSV file to write per-finding rows to")
	flag.Parse()

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		log.Fatal("benchmark: GITHUB_TOKEN environment variable is required")
	}

	cfg, err := loadRepoConfig(*reposFile)
	if err != nil {
		log.Fatalf("benchmark: %v", err)
	}

	catalog, err := rules.LoadCatalog(*rulesFile)
	if err != nil {
		log.Fatalf("benchmark: failed to load rules catalog: %v", err)
	}

	fetcher := github.NewFetcher(token)

	var allFindings []findingRow
	totalPRsScanned := 0
	totalPRsErrored := 0
	totalFilesScanned := 0
	riskCounts := map[string]int{}

	for _, repo := range cfg.Repos {
		log.Printf("benchmark: listing merged PRs for %s/%s (limit %d)", repo.Owner, repo.Name, *perRepoLimit)

		prs, err := listWithRetry(fetcher, repo.Owner, repo.Name, *perRepoLimit)
		if err != nil {
			log.Printf("benchmark: WARNING failed to list PRs for %s/%s: %v", repo.Owner, repo.Name, err)
			continue
		}
		log.Printf("benchmark: %s/%s — %d merged PRs found", repo.Owner, repo.Name, len(prs))

		for _, pr := range prs {
			results, err := scanWithRetry(fetcher, catalog, repo.Owner, repo.Name, pr.Number, pr.HeadSHA)
			if err != nil {
				log.Printf("benchmark: WARNING failed to scan %s/%s PR #%d: %v", repo.Owner, repo.Name, pr.Number, err)
				totalPRsErrored++
				time.Sleep(time.Duration(*delayMs) * time.Millisecond)
				continue
			}

			totalPRsScanned++

			for _, r := range results {
				totalFilesScanned++
				for _, f := range r.Findings {
					riskCounts[string(f.Risk)]++
					allFindings = append(allFindings, findingRow{
						Repo:     repo.Owner + "/" + repo.Name,
						PRNumber: pr.Number,
						MergedAt: pr.MergedAt,
						File:     f.File,
						Line:     f.Line,
						Risk:     string(f.Risk),
						CWE:      f.CWE,
						Reason:   f.Reason,
					})
				}
			}

			time.Sleep(time.Duration(*delayMs) * time.Millisecond)
		}
	}

	if err := writeCSV(*outputFile, allFindings); err != nil {
		log.Fatalf("benchmark: failed to write output: %v", err)
	}

	fmt.Println()
	fmt.Println("=== RouteWarden Benchmark Summary ===")
	fmt.Printf("PRs scanned successfully: %d\n", totalPRsScanned)
	fmt.Printf("PRs skipped due to errors: %d\n", totalPRsErrored)
	fmt.Printf("Files scanned: %d\n", totalFilesScanned)
	fmt.Printf("Total findings: %d\n", len(allFindings))
	for risk, count := range riskCounts {
		fmt.Printf("  %s: %d\n", risk, count)
	}
	if totalPRsScanned > 0 {
		withFindings := countUniquePRsWithFindings(allFindings)
		fmt.Printf("PRs with at least 1 finding: %d (%.1f%%)\n",
			withFindings, 100*float64(withFindings)/float64(totalPRsScanned))
	}
	fmt.Printf("Results written to: %s\n", *outputFile)
}

// isRateLimitError detects GitHub's rate limit responses (both primary and
// the stricter "secondary" limit triggered by request bursts) so callers
// can back off instead of just giving up.
func isRateLimitError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "403") &&
		(strings.Contains(msg, "rate limit") || strings.Contains(msg, "abuse"))
}

// listWithRetry wraps ListRecentMergedPullRequests with a single 60-second
// backoff-and-retry if GitHub's rate limit is hit — that limit resets on a
// rolling window, so a short wait is usually enough to recover.
func listWithRetry(fetcher *github.Fetcher, owner, repo string, limit int) ([]github.PullRequestSummary, error) {
	prs, err := fetcher.ListRecentMergedPullRequests(owner, repo, limit)
	if err == nil || !isRateLimitError(err) {
		return prs, err
	}
	log.Printf("benchmark: rate limited listing PRs for %s/%s — waiting 60s before retrying", owner, repo)
	time.Sleep(60 * time.Second)
	return fetcher.ListRecentMergedPullRequests(owner, repo, limit)
}

// scanWithRetry does the same for a single PR scan.
func scanWithRetry(fetcher *github.Fetcher, catalog *rules.Catalog, owner, repo string, prNumber int, headSHA string) ([]pipeline.FileResult, error) {
	results, err := pipeline.ScanPullRequestFiles(fetcher, catalog, owner, repo, prNumber, headSHA)
	if err == nil || !isRateLimitError(err) {
		return results, err
	}
	log.Printf("benchmark: rate limited scanning %s/%s PR #%d — waiting 60s before retrying", owner, repo, prNumber)
	time.Sleep(60 * time.Second)
	return pipeline.ScanPullRequestFiles(fetcher, catalog, owner, repo, prNumber, headSHA)
}

func countUniquePRsWithFindings(rows []findingRow) int {
	seen := make(map[string]bool)
	for _, r := range rows {
		seen[fmt.Sprintf("%s#%d", r.Repo, r.PRNumber)] = true
	}
	return len(seen)
}

func writeCSV(path string, rows []findingRow) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write([]string{"repo", "pr_number", "merged_at", "file", "line", "risk", "cwe", "reason"}); err != nil {
		return err
	}

	for _, r := range rows {
		if err := w.Write([]string{
			r.Repo, fmt.Sprintf("%d", r.PRNumber), r.MergedAt, r.File,
			fmt.Sprintf("%d", r.Line), r.Risk, r.CWE, r.Reason,
		}); err != nil {
			return err
		}
	}

	return nil
}
