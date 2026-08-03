package diff

import (
	"strings"
	"testing"
)

const sampleDiff = `diff --git a/routes.ts b/routes.ts
index 1111111..2222222 100644
--- a/routes.ts
+++ b/routes.ts
@@ -10,5 +10,6 @@ import { Router } from "express";
 const router = Router();
-router.post("/users", (req, res) => {
+router.post("/users", requireAuth, (req, res) => {
+  console.log("creating user");
   res.json({ ok: true });
 });
 export default router;
`

func TestParseAddedLines(t *testing.T) {
	added, err := ParseAddedLines(strings.NewReader(sampleDiff))
	if err != nil {
		t.Fatalf("ParseAddedLines returned error: %v", err)
	}

	lines, ok := added["routes.ts"]
	if !ok {
		t.Fatalf("expected an entry for routes.ts, got: %v", added)
	}

	want := []int{11, 12}
	if len(lines) != len(want) {
		t.Fatalf("got %d added lines %v, want %d %v", len(lines), lines, len(want), want)
	}
	for i, l := range lines {
		if l != want[i] {
			t.Fatalf("added lines = %v, want %v", lines, want)
		}
	}
}
