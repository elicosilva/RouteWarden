package rules

import (
	"testing"

	"github.com/routewarden/routewarden/pkg/ast"
	"github.com/routewarden/routewarden/pkg/output"
)

func testCatalog() *Catalog {
	return NewCatalog(map[string][]string{
		"generic": {"requireAuth", "AuthGuard"},
	})
}

func TestCheckMutableNoAuth_FlagsUnprotectedMutableRoute(t *testing.T) {
	route := ast.RouteNode{StartLine: 6, EndLine: 8, Method: "POST", Route: "/users"}

	finding := CheckMutableNoAuth("routes.ts", route, testCatalog())
	if finding == nil {
		t.Fatal("expected a HIGH finding for a mutable route with no middleware, got nil")
	}
	if finding.Risk != output.RiskHigh {
		t.Errorf("expected RiskHigh, got %s", finding.Risk)
	}
	if finding.Line != 6 {
		t.Errorf("expected finding on line 6, got %d", finding.Line)
	}
	if finding.CWE != "CWE-306" {
		t.Errorf("expected CWE-306, got %s", finding.CWE)
	}
}

func TestCheckMutableNoAuth_IgnoresRouteWithKnownAuthMiddleware(t *testing.T) {
	route := ast.RouteNode{
		StartLine: 6, EndLine: 8, Method: "POST", Route: "/users",
		Middlewares: []string{"requireAuth"},
	}

	if finding := CheckMutableNoAuth("routes.ts", route, testCatalog()); finding != nil {
		t.Errorf("expected no finding for a route with known auth middleware, got: %+v", finding)
	}
}

func TestCheckMutableNoAuth_FlagsRouteWithUnrecognizedMiddleware(t *testing.T) {
	// A middleware IS present, but it's not in the catalog (e.g. a logger).
	// This is the key behavior change from Fase 4's "any middleware counts"
	// heuristic: now it must be a *known* auth middleware.
	route := ast.RouteNode{
		StartLine: 6, EndLine: 8, Method: "POST", Route: "/users",
		Middlewares: []string{"requestLogger"},
	}

	finding := CheckMutableNoAuth("routes.ts", route, testCatalog())
	if finding == nil {
		t.Fatal("expected a finding: requestLogger is not a known auth middleware")
	}
}

func TestCheckMutableNoAuth_IgnoresNonMutableMethod(t *testing.T) {
	route := ast.RouteNode{StartLine: 6, EndLine: 8, Method: "GET", Route: "/health"}

	if finding := CheckMutableNoAuth("routes.ts", route, testCatalog()); finding != nil {
		t.Errorf("expected no finding for a GET route, got: %+v", finding)
	}
}

func TestCheckMutableNoAuth_IgnoresKnownPublicAuthRoutes(t *testing.T) {
	catalog := testCatalog()
	catalog.SetPublicRouteKeywords([]string{"login", "register"})

	loginRoute := ast.RouteNode{StartLine: 1, EndLine: 3, Method: "POST", Route: "/users/login"}
	if finding := CheckMutableNoAuth("auth.ts", loginRoute, catalog); finding != nil {
		t.Errorf("expected no finding for a login route, got: %+v", finding)
	}

	registerRoute := ast.RouteNode{StartLine: 5, EndLine: 7, Method: "POST", Route: "/auth/register"}
	if finding := CheckMutableNoAuth("auth.ts", registerRoute, catalog); finding != nil {
		t.Errorf("expected no finding for a register route, got: %+v", finding)
	}

	// A bare "/users" POST is intentionally NOT exempted — could be a real
	// admin-only user-creation endpoint in some apps.
	bareUsersRoute := ast.RouteNode{StartLine: 9, EndLine: 11, Method: "POST", Route: "/users"}
	if finding := CheckMutableNoAuth("auth.ts", bareUsersRoute, catalog); finding == nil {
		t.Error("expected bare POST /users to still be flagged (not blanket-exempted)")
	}
}
