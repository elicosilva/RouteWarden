package rules

import (
	"testing"

	"github.com/routewarden/routewarden/pkg/ast"
	"github.com/routewarden/routewarden/pkg/output"
)

func TestCheckResponseLeak_FlagsSensitiveKey(t *testing.T) {
	route := ast.RouteNode{
		StartLine: 6, EndLine: 8, Method: "POST", Route: "/login",
		ResponseKeys: []string{"userId", "token"},
	}

	finding := CheckResponseLeak("auth.ts", route)
	if finding == nil {
		t.Fatal("expected a MEDIUM finding for a response containing a 'token' key")
	}
	if finding.Risk != output.RiskMedium {
		t.Errorf("expected RiskMedium, got %s", finding.Risk)
	}
	if finding.CWE != "CWE-200" {
		t.Errorf("expected CWE-200, got %s", finding.CWE)
	}
}

func TestCheckResponseLeak_IgnoresCleanResponse(t *testing.T) {
	route := ast.RouteNode{
		StartLine: 6, EndLine: 8, Method: "GET", Route: "/health",
		ResponseKeys: []string{"status", "uptime"},
	}

	if finding := CheckResponseLeak("routes.ts", route); finding != nil {
		t.Errorf("expected no finding for a clean response, got: %+v", finding)
	}
}

func TestCheckResponseLeak_CaseInsensitiveSubstringMatch(t *testing.T) {
	route := ast.RouteNode{
		StartLine: 1, EndLine: 3, Method: "POST", Route: "/debug",
		ResponseKeys: []string{"mockBypassFlag"},
	}

	if finding := CheckResponseLeak("routes.ts", route); finding == nil {
		t.Error("expected a finding: 'mockBypassFlag' contains both 'mock' and 'bypass'")
	}
}
