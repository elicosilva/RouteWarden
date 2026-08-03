package scanner

import (
	"strings"
	"testing"

	"github.com/routewarden/routewarden/pkg/ast"
	"github.com/routewarden/routewarden/pkg/diff"
	"github.com/routewarden/routewarden/pkg/output"
	"github.com/routewarden/routewarden/pkg/scanner/rules"
)

const sampleSource = `import { Router } from "express";
const router = Router();
router.get("/health", (req, res) => {
  res.json({ status: "ok" });
});
router.post("/users", (req, res) => {
  res.json({ ok: true });
});
export default router;
`

const sampleDiff = `diff --git a/routes.ts b/routes.ts
index 1111111..2222222 100644
--- a/routes.ts
+++ b/routes.ts
@@ -3,4 +3,7 @@ const router = Router();
 router.get("/health", (req, res) => {
   res.json({ status: "ok" });
 });
+router.post("/users", (req, res) => {
+  res.json({ ok: true });
+});
 export default router;
`

func TestScanEndToEnd_HighRiskFindingOnAddedRouteOnly(t *testing.T) {
	addedByFile, err := diff.ParseAddedLines(strings.NewReader(sampleDiff))
	if err != nil {
		t.Fatalf("ParseAddedLines: %v", err)
	}

	addedLines, ok := addedByFile["routes.ts"]
	if !ok {
		t.Fatalf("expected added lines for routes.ts, got: %v", addedByFile)
	}

	idx, err := ast.Parse("routes.ts", []byte(sampleSource))
	if err != nil {
		t.Fatalf("ast.Parse: %v", err)
	}

	routes, err := ast.ExtractExpressRoutes(idx)
	if err != nil {
		t.Fatalf("ExtractExpressRoutes: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("expected 2 routes extracted (GET /health, POST /users), got %d: %+v", len(routes), routes)
	}

	catalog := rules.NewCatalog(map[string][]string{"generic": {"requireAuth"}})
	findings := Scan("routes.ts", addedLines, routes, catalog)

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding (only the diff-added POST route), got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if f.Risk != output.RiskHigh {
		t.Errorf("expected RiskHigh, got %s", f.Risk)
	}
	if f.Line != 6 {
		t.Errorf("expected finding on line 6, got %d", f.Line)
	}
	if f.File != "routes.ts" {
		t.Errorf("expected file routes.ts, got %s", f.File)
	}
}

const responseLeakSource = `import { Router } from "express";
const router = Router();
router.get("/profile", requireAuth, (req, res) => {
  res.json({ userId: 1, token: "abc123" });
});
export default router;
`

const responseLeakDiff = `diff --git a/routes.ts b/routes.ts
index 1111111..2222222 100644
--- a/routes.ts
+++ b/routes.ts
@@ -2,2 +2,5 @@
 const router = Router();
+router.get("/profile", requireAuth, (req, res) => {
+  res.json({ userId: 1, token: "abc123" });
+});
 export default router;
`

func TestScanEndToEnd_MediumRiskResponseLeakFinding(t *testing.T) {
	addedByFile, err := diff.ParseAddedLines(strings.NewReader(responseLeakDiff))
	if err != nil {
		t.Fatalf("ParseAddedLines: %v", err)
	}

	addedLines, ok := addedByFile["routes.ts"]
	if !ok {
		t.Fatalf("expected added lines for routes.ts, got: %v", addedByFile)
	}

	idx, err := ast.Parse("routes.ts", []byte(responseLeakSource))
	if err != nil {
		t.Fatalf("ast.Parse: %v", err)
	}

	routes, err := ast.ExtractExpressRoutes(idx)
	if err != nil {
		t.Fatalf("ExtractExpressRoutes: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d: %+v", len(routes), routes)
	}

	// GET is not mutable and requireAuth is a known middleware, so
	// mutable_no_auth must NOT fire here — only response_leak should.
	catalog := rules.NewCatalog(map[string][]string{"generic": {"requireAuth"}})
	findings := Scan("routes.ts", addedLines, routes, catalog)

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding (MEDIUM response leak only), got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if f.Risk != output.RiskMedium {
		t.Errorf("expected RiskMedium, got %s", f.Risk)
	}
	if f.CWE != "CWE-200" {
		t.Errorf("expected CWE-200, got %s", f.CWE)
	}
}
