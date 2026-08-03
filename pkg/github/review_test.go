package github

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/routewarden/routewarden/pkg/output"
)

func TestPostReviewComment_SendsCorrectRequest(t *testing.T) {
	var capturedBody ReviewCommentRequest
	var capturedPath, capturedMethod, capturedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedMethod = r.Method
		capturedPath = r.URL.Path
		capturedAuth = r.Header.Get("Authorization")

		if err := json.NewDecoder(r.Body).Decode(&capturedBody); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}

		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id": 1}`))
	}))
	defer server.Close()

	f := &Fetcher{Token: "test-token", APIBase: server.URL, HTTPClient: server.Client()}

	err := f.PostReviewComment("myorg", "myrepo", 42, "abc123sha", "routes.ts", 6, "HIGH risk finding")
	if err != nil {
		t.Fatalf("PostReviewComment returned error: %v", err)
	}

	if capturedMethod != http.MethodPost {
		t.Errorf("expected POST, got %s", capturedMethod)
	}
	wantPath := "/repos/myorg/myrepo/pulls/42/comments"
	if capturedPath != wantPath {
		t.Errorf("expected path %s, got %s", wantPath, capturedPath)
	}
	if capturedAuth != "Bearer test-token" {
		t.Errorf("expected 'Bearer test-token', got %s", capturedAuth)
	}
	if capturedBody.Line != 6 {
		t.Errorf("expected line 6, got %d", capturedBody.Line)
	}
	if capturedBody.Side != "RIGHT" {
		t.Errorf("expected side RIGHT, got %s", capturedBody.Side)
	}
	if capturedBody.CommitID != "abc123sha" {
		t.Errorf("expected commit_id abc123sha, got %s", capturedBody.CommitID)
	}
	if capturedBody.Path != "routes.ts" {
		t.Errorf("expected path routes.ts, got %s", capturedBody.Path)
	}
}

func TestPostReviewComment_NeverUsesLegacyPositionField(t *testing.T) {
	var rawBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&rawBody)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	f := &Fetcher{Token: "t", APIBase: server.URL, HTTPClient: server.Client()}
	if err := f.PostReviewComment("o", "r", 1, "sha", "f.ts", 1, "body"); err != nil {
		t.Fatalf("PostReviewComment: %v", err)
	}

	if _, exists := rawBody["position"]; exists {
		t.Error("request body must never include the legacy 'position' field (rule R1)")
	}
	if _, exists := rawBody["line"]; !exists {
		t.Error("request body must include 'line'")
	}
	if side, _ := rawBody["side"].(string); side != "RIGHT" {
		t.Errorf("expected side RIGHT, got %v", rawBody["side"])
	}
}

func TestPostReviewComment_ErrorOnNonCreatedStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{"message": "Validation Failed"}`))
	}))
	defer server.Close()

	f := &Fetcher{Token: "t", APIBase: server.URL, HTTPClient: server.Client()}
	err := f.PostReviewComment("o", "r", 1, "sha", "f.ts", 1, "body")
	if err == nil {
		t.Error("expected an error for a non-201 response")
	}
}

func TestFormatFindingComment(t *testing.T) {
	f := output.Finding{
		File:       "routes.ts",
		Line:       6,
		Risk:       output.RiskHigh,
		CWE:        "CWE-306",
		Reason:     "POST /users has no auth middleware",
		Confidence: 0.7,
	}

	comment := FormatFindingComment(f)
	if !strings.Contains(comment, "HIGH") {
		t.Error("expected comment to mention HIGH risk")
	}
	if !strings.Contains(comment, "CWE-306") {
		t.Error("expected comment to mention CWE-306")
	}
	if !strings.Contains(comment, "POST /users has no auth middleware") {
		t.Error("expected comment to include the reason")
	}
}
