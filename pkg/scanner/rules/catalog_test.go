package rules

import "testing"

func TestCatalog_IsKnownAuthMiddleware(t *testing.T) {
	catalog := NewCatalog(map[string][]string{
		"clerk":   {"requireAuth", "clerkMiddleware"},
		"generic": {"AuthGuard"},
	})

	cases := []struct {
		identifier string
		want       bool
	}{
		{"requireAuth", true},
		{"clerkMiddleware", true},
		{"AuthGuard", true},
		{"myLib.requireAuth", true},        // member expression, matches last segment
		{"AuthGuard(Role.ADMIN)", true},    // decorator call, matches before '('
		{"loggerMiddleware", false},        // unrelated middleware
		{"rateLimiter", false},
	}

	for _, tc := range cases {
		got := catalog.IsKnownAuthMiddleware(tc.identifier)
		if got != tc.want {
			t.Errorf("IsKnownAuthMiddleware(%q) = %v, want %v", tc.identifier, got, tc.want)
		}
	}
}

func TestCatalog_NilCatalogTrustsNothing(t *testing.T) {
	var catalog *Catalog
	if catalog.IsKnownAuthMiddleware("requireAuth") {
		t.Error("expected nil catalog to never recognize any middleware")
	}
}

func TestCatalog_QualifiedEntryRequiresFullMatch(t *testing.T) {
	catalog := NewCatalog(map[string][]string{
		"realworld": {"auth.required"},
	})

	cases := []struct {
		identifier string
		want       bool
	}{
		{"auth.required", true},
		{"auth.required()", true},        // call form, args stripped
		{"required", false},              // bare last segment alone: NOT trusted
		{"validation.required", false},   // different qualifier, same last segment
		{"auth.optional", false},         // different qualified name entirely
	}

	for _, tc := range cases {
		got := catalog.IsKnownAuthMiddleware(tc.identifier)
		if got != tc.want {
			t.Errorf("IsKnownAuthMiddleware(%q) = %v, want %v", tc.identifier, got, tc.want)
		}
	}
}

func TestCatalog_IsPublicRoute(t *testing.T) {
	catalog := NewCatalog(nil)
	catalog.SetPublicRouteKeywords([]string{"login", "register", "forgot-password"})

	cases := []struct {
		route string
		want  bool
	}{
		{"/users/login", true},
		{"/auth/register", true},
		{"/account/forgot-password", true},
		{"/users", false},        // bare collection route: NOT exempted (rule: avoid false negatives)
		{"/users/:id", false},
		{"", false},
	}

	for _, tc := range cases {
		if got := catalog.IsPublicRoute(tc.route); got != tc.want {
			t.Errorf("IsPublicRoute(%q) = %v, want %v", tc.route, got, tc.want)
		}
	}
}

func TestCatalog_NilCatalogIsPublicRouteFalse(t *testing.T) {
	var catalog *Catalog
	if catalog.IsPublicRoute("/users/login") {
		t.Error("expected nil catalog to never treat any route as public")
	}
}
