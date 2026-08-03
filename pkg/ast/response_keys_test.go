package ast

import "testing"

const responseLeakSample = `import { Router } from "express";
const router = Router();
router.post("/login", (req, res) => {
  res.json({ userId: 1, token: "abc123" });
});
export default router;
`

func TestExtractExpressRoutes_PopulatesResponseKeys(t *testing.T) {
	idx, err := Parse("routes.ts", []byte(responseLeakSample))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	routes, err := ExtractExpressRoutes(idx)
	if err != nil {
		t.Fatalf("ExtractExpressRoutes: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d: %+v", len(routes), routes)
	}

	keys := routes[0].ResponseKeys
	want := map[string]bool{"userId": true, "token": true}
	if len(keys) != len(want) {
		t.Fatalf("expected %d response keys, got %d: %v", len(want), len(keys), keys)
	}
	for _, k := range keys {
		if !want[k] {
			t.Errorf("unexpected response key %q", k)
		}
	}
}
