// Package rules contains RouteWarden's deterministic detection rules
// (rule R3: Go filters before any LLM is involved).
package rules

import (
	"fmt"

	"github.com/routewarden/routewarden/pkg/ast"
	"github.com/routewarden/routewarden/pkg/output"
)

var mutableMethods = map[string]bool{
	"POST": true, "PUT": true, "DELETE": true, "PATCH": true,
}

// CheckMutableNoAuth is the HIGH-risk rule: a mutable HTTP method
// (POST/PUT/DELETE/PATCH) with no *known* auth middleware attached to it,
// and not a known-public auth entry-point (login, register, ...).
func CheckMutableNoAuth(file string, route ast.RouteNode, catalog *Catalog) *output.Finding {
	if !mutableMethods[route.Method] {
		return nil
	}
	if hasKnownAuthMiddleware(route.Middlewares, catalog) {
		return nil
	}
	if catalog.IsPublicRoute(route.Route) {
		return nil
	}

	return &output.Finding{
		File:       file,
		Line:       route.StartLine,
		Risk:       output.RiskHigh,
		CWE:        "CWE-306", // Missing Authentication for Critical Function
		Reason:     fmt.Sprintf("%s %s has a mutable method with no recognized authentication middleware", route.Method, routeLabel(route.Route)),
		Confidence: 0.7,
	}
}

func hasKnownAuthMiddleware(middlewares []string, catalog *Catalog) bool {
	for _, m := range middlewares {
		if catalog.IsKnownAuthMiddleware(m) {
			return true
		}
	}
	return false
}

func routeLabel(route string) string {
	if route == "" {
		return "route (path determined by file location)"
	}
	return route
}
