// Package pipeline holds the read-only core of a RouteWarden scan: fetch a
// PR's changed files, cross-reference with the diff, parse AST, run rules.
// It never posts anything anywhere (rule R7) — that decision belongs to
// the caller. cmd/server uses this and then posts comments; cmd/benchmark
// uses the exact same function and only measures, so both stay in sync
// with the same underlying logic.
package pipeline

import (
	"fmt"
	"strings"

	"github.com/routewarden/routewarden/pkg/ast"
	"github.com/routewarden/routewarden/pkg/diff"
	"github.com/routewarden/routewarden/pkg/github"
	"github.com/routewarden/routewarden/pkg/output"
	"github.com/routewarden/routewarden/pkg/scanner"
	"github.com/routewarden/routewarden/pkg/scanner/rules"
)

// FileResult holds the outcome of scanning one changed file within a PR.
// Skipped is non-empty (and Findings is nil) when the file couldn't be
// scanned — a fetch/parse error, not a security finding.
type FileResult struct {
	Filename string
	Findings []output.Finding
	Skipped  string
}

// ScanPullRequestFiles fetches a PR's changed files (rule R5), extracts
// routes for every supported framework (rule R4), and runs the
// deterministic rules (rule R3) against whatever overlaps the diff's added
// lines. It only reads — fetcher.PostReviewComment is never called here.
func ScanPullRequestFiles(fetcher *github.Fetcher, catalog *rules.Catalog, owner, repo string, prNumber int, headSHA string) ([]FileResult, error) {
	files, err := fetcher.FetchPullRequestFiles(owner, repo, prNumber)
	if err != nil {
		return nil, fmt.Errorf("fetch PR files: %w", err)
	}

	var results []FileResult

	for _, file := range files {
		if !isSupportedSourceFile(file.Filename) {
			continue
		}

		diffText, ok := file.UnifiedDiff()
		if !ok {
			continue // removed, binary, or no-op rename
		}

		addedByFile, err := diff.ParseAddedLines(strings.NewReader(diffText))
		if err != nil {
			results = append(results, FileResult{
				Filename: file.Filename,
				Skipped:  fmt.Sprintf("diff parse error: %v", err),
			})
			continue
		}

		addedLines, ok := addedByFile[file.Filename]
		if !ok || len(addedLines) == 0 {
			continue
		}

		content, err := fetcher.FetchFile(owner, repo, file.Filename, headSHA)
		if err != nil {
			results = append(results, FileResult{
				Filename: file.Filename,
				Skipped:  fmt.Sprintf("fetch content error: %v", err),
			})
			continue
		}

		idx, err := ast.Parse(file.Filename, content)
		if err != nil {
			results = append(results, FileResult{
				Filename: file.Filename,
				Skipped:  fmt.Sprintf("AST parse error: %v", err),
			})
			continue
		}

		var routes []ast.RouteNode
		if expressRoutes, err := ast.ExtractExpressRoutes(idx); err == nil {
			routes = append(routes, expressRoutes...)
		}
		routes = append(routes, ast.ExtractNestJSRoutes(idx)...)
		routes = append(routes, ast.ExtractNextJSRoutes(idx)...)

		findings := scanner.Scan(file.Filename, addedLines, routes, catalog)
		results = append(results, FileResult{Filename: file.Filename, Findings: findings})
	}

	return results, nil
}

// isSupportedSourceFile filters to the TS/JS extensions RouteWarden's AST
// layer understands (rule R4).
func isSupportedSourceFile(path string) bool {
	for _, ext := range []string{".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"} {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}
