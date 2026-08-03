package rules

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Catalog is the declarative allowlist of known auth-middleware identifiers
// (rule R4), plus a list of route-path keywords that are always considered
// public regardless of middleware (login, register, etc.) — both loaded
// from rules.yaml at runtime, never embedded in the binary, so operators
// can extend them without recompiling.
type Catalog struct {
	Providers           map[string][]string `yaml:"providers"`
	PublicRouteKeywords []string             `yaml:"public_route_keywords"`

	lookup           map[string]bool
	publicKeywordsLC []string
}

// LoadCatalog reads and parses a rules.yaml file at path.
func LoadCatalog(path string) (*Catalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("rules: read catalog %q: %w", path, err)
	}

	var parsed Catalog
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("rules: parse catalog %q: %w", path, err)
	}

	c := NewCatalog(parsed.Providers)
	c.SetPublicRouteKeywords(parsed.PublicRouteKeywords)
	return c, nil
}

// NewCatalog builds a Catalog directly from a providers map, without
// reading a file. Used by LoadCatalog and directly by tests. Public route
// keywords default to empty; set them with SetPublicRouteKeywords if
// needed.
func NewCatalog(providers map[string][]string) *Catalog {
	c := &Catalog{Providers: providers, lookup: make(map[string]bool)}
	for _, names := range providers {
		for _, name := range names {
			c.lookup[strings.ToLower(name)] = true
		}
	}
	return c
}

// SetPublicRouteKeywords configures which route-path keywords are always
// treated as public (never flagged by mutable_no_auth), regardless of
// middleware. This is intentionally narrow: only unambiguous auth
// entry-points (login, register, ...) belong here — anything broader (like
// exempting bare "/users") risks hiding a genuine missing-auth
// vulnerability, which is a worse outcome than an easily-dismissed false
// positive (rule R1: a human always reviews the comment anyway).
func (c *Catalog) SetPublicRouteKeywords(keywords []string) {
	c.PublicRouteKeywords = keywords
	c.publicKeywordsLC = make([]string, len(keywords))
	for i, k := range keywords {
		c.publicKeywordsLC[i] = strings.ToLower(k)
	}
}

// IsPublicRoute reports whether route's path contains a configured public
// keyword (case-insensitive substring match). A nil catalog or empty route
// always returns false.
func (c *Catalog) IsPublicRoute(route string) bool {
	if c == nil || route == "" {
		return false
	}
	lower := strings.ToLower(route)
	for _, kw := range c.publicKeywordsLC {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// IsKnownAuthMiddleware reports whether identifier matches a known
// auth-middleware entry from the catalog. Two kinds of catalog entries are
// supported:
//
//   - Bare entries (no dot), e.g. "requireAuth" or "AuthGuard": matched
//     against just the final segment of identifier, so "myLib.requireAuth"
//     and "requireAuth(Role.ADMIN)" both match.
//   - Qualified entries (contain a dot), e.g. "auth.required": matched
//     against the identifier's full text (call args stripped). This is
//     necessary because the final segment alone ("required") is too
//     generic to safely treat as an auth signal on its own.
//
// A nil catalog always returns false, so callers can safely pass a nil
// catalog to mean "trust nothing".
func (c *Catalog) IsKnownAuthMiddleware(identifier string) bool {
	if c == nil {
		return false
	}

	if c.lookup[strings.ToLower(stripCallArgs(identifier))] {
		return true
	}

	return c.lookup[strings.ToLower(lastSegment(identifier))]
}

// stripCallArgs removes a trailing call's arguments, e.g.
// "auth.required(Role.ADMIN)" -> "auth.required". Leaves bare identifiers
// (no parens) untouched.
func stripCallArgs(identifier string) string {
	if idx := strings.IndexByte(identifier, '('); idx != -1 {
		identifier = identifier[:idx]
	}
	return strings.TrimSpace(identifier)
}

// lastSegment strips call arguments and any member-access prefix from an
// identifier, e.g. "myLib.AuthGuard(Role.ADMIN)" -> "AuthGuard".
func lastSegment(identifier string) string {
	identifier = stripCallArgs(identifier)
	if idx := strings.LastIndexByte(identifier, '.'); idx != -1 {
		identifier = identifier[idx+1:]
	}
	return strings.TrimSpace(identifier)
}
