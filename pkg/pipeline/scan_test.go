package pipeline

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/routewarden/routewarden/pkg/github"
	"github.com/routewarden/routewarden/pkg/output"
	"github.com/routewarden/routewarden/pkg/scanner/rules"
)

const pipelineSampleSource = `import { Router } from "express";
const router = Router();
router.get("/health", (req, res) => {
  res.json({ status: "ok" });
});
router.post("/users", (req, res) => {
  res.json({ ok: true });
});
export default router;
`

const pipelineSamplePatch = `@@ -3,4 +3,7 @@
 router.get("/health", (req, res) => {
   res.json({ status: "ok" });
 });
+router.post("/users", (req, res) => {
+  res.json({ ok: true });
+});
 export default router;`

func TestScanPullRequestFiles_EndToEnd(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/repos/owner/repo/pulls/1/files", func(w http.ResponseWriter, r *http.Request) {
		files := []map[string]string{
			{"filename": "routes.ts", "status": "modified", "patch": pipelineSamplePatch},
		}
		json.NewEncoder(w).Encode(files)
	})

	mux.HandleFunc("/repos/owner/repo/contents/routes.ts", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]string{
			"type":     "file",
			"encoding": "base64",
			"content":  base64.StdEncoding.EncodeToString([]byte(pipelineSampleSource)),
		}
		json.NewEncoder(w).Encode(resp)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	fetcher := &github.Fetcher{Token: "t", APIBase: server.URL, HTTPClient: server.Client()}
	catalog := rules.NewCatalog(map[string][]string{"generic": {"requireAuth"}})

	results, err := ScanPullRequestFiles(fetcher, catalog, "owner", "repo", 1, "headsha")
	if err != nil {
		t.Fatalf("ScanPullRequestFiles: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 file result, got %d: %+v", len(results), results)
	}

	r := results[0]
	if r.Skipped != "" {
		t.Fatalf("expected no skip, got: %s", r.Skipped)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("expected 1 finding (POST /users, no auth), got %d: %+v", len(r.Findings), r.Findings)
	}
	if r.Findings[0].Risk != output.RiskHigh {
		t.Errorf("expected RiskHigh, got %s", r.Findings[0].Risk)
	}
}

func TestScanPullRequestFiles_IgnoresUnsupportedFileTypes(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/pulls/1/files", func(w http.ResponseWriter, r *http.Request) {
		files := []map[string]string{
			{"filename": "README.md", "status": "modified", "patch": "@@ -1,1 +1,2 @@\n line\n+new line"},
		}
		json.NewEncoder(w).Encode(files)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	fetcher := &github.Fetcher{Token: "t", APIBase: server.URL, HTTPClient: server.Client()}
	results, err := ScanPullRequestFiles(fetcher, nil, "owner", "repo", 1, "sha")
	if err != nil {
		t.Fatalf("ScanPullRequestFiles: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for a non-source file, got %d: %+v", len(results), results)
	}
}
