package github

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListRecentMergedPullRequests_FiltersUnmergedAndPaginates(t *testing.T) {
	page1 := `[
		{"number": 3, "merged_at": "2026-01-03T00:00:00Z", "head": {"sha": "sha3"}},
		{"number": 2, "merged_at": null, "head": {"sha": "sha2"}},
		{"number": 1, "merged_at": "2026-01-01T00:00:00Z", "head": {"sha": "sha1"}}
	]`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		w.Header().Set("Content-Type", "application/json")
		if page == "1" || page == "" {
			fmt.Fprint(w, page1)
		} else {
			fmt.Fprint(w, "[]")
		}
	}))
	defer server.Close()

	f := &Fetcher{Token: "t", APIBase: server.URL, HTTPClient: server.Client()}

	results, err := f.ListRecentMergedPullRequests("owner", "repo", 10)
	if err != nil {
		t.Fatalf("ListRecentMergedPullRequests: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 merged PRs (unmerged #2 filtered out), got %d: %+v", len(results), results)
	}
	if results[0].Number != 3 || results[1].Number != 1 {
		t.Errorf("expected PRs #3 then #1, got %+v", results)
	}
}

func TestListRecentMergedPullRequests_RespectsLimit(t *testing.T) {
	page1 := `[
		{"number": 1, "merged_at": "2026-01-01T00:00:00Z", "head": {"sha": "a"}},
		{"number": 2, "merged_at": "2026-01-01T00:00:00Z", "head": {"sha": "b"}},
		{"number": 3, "merged_at": "2026-01-01T00:00:00Z", "head": {"sha": "c"}}
	]`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, page1)
	}))
	defer server.Close()

	f := &Fetcher{Token: "t", APIBase: server.URL, HTTPClient: server.Client()}

	results, err := f.ListRecentMergedPullRequests("owner", "repo", 2)
	if err != nil {
		t.Fatalf("ListRecentMergedPullRequests: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected exactly 2 results (limit), got %d", len(results))
	}
}
