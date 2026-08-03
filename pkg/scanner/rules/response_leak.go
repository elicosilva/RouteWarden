package rules

import (
	"fmt"
	"strings"

	"github.com/routewarden/routewarden/pkg/ast"
	"github.com/routewarden/routewarden/pkg/output"
)

// sensitiveKeyPatterns are substrings (case-insensitive) that flag a
// response payload key as potentially leaking something it shouldn't:
// real secrets (token/password/secret) or debug/test scaffolding that
// should never reach production responses (mock/bypass).
var sensitiveKeyPatterns = []string{"token", "password", "secret", "mock", "bypass"}

// CheckResponseLeak is the MEDIUM-risk rule: a route's response payload
// (res.json/res.send/NextResponse.json/...) includes a key whose name
// matches a sensitive pattern. This is a naming heuristic, not a value
// inspection — RouteWarden never executes code or inspects runtime values
// (rule R7), so a field named "token" is flagged regardless of what it
// actually contains.
func CheckResponseLeak(file string, route ast.RouteNode) *output.Finding {
	key, matched := firstSensitiveKey(route.ResponseKeys)
	if !matched {
		return nil
	}

	return &output.Finding{
		File:       file,
		Line:       route.StartLine,
		Risk:       output.RiskMedium,
		CWE:        "CWE-200", // Exposure of Sensitive Information to an Unauthorized Actor
		Reason:     fmt.Sprintf("%s %s response includes a field named %q, which may leak sensitive data", route.Method, routeLabel(route.Route), key),
		Confidence: 0.5,
	}
}

func firstSensitiveKey(keys []string) (string, bool) {
	for _, k := range keys {
		lower := strings.ToLower(k)
		for _, pattern := range sensitiveKeyPatterns {
			if strings.Contains(lower, pattern) {
				return k, true
			}
		}
	}
	return "", false
}
