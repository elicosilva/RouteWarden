package github

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
)

const samplePullRequestPayload = `{
  "action": "opened",
  "number": 42,
  "pull_request": {
    "head": {"sha": "abc123", "ref": "feature-branch"},
    "base": {"sha": "def456", "ref": "main"}
  },
  "repository": {
    "name": "myrepo",
    "owner": {"login": "myorg"}
  }
}`

func sign(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifySignature_Valid(t *testing.T) {
	secret := "test-secret"
	payload := []byte(samplePullRequestPayload)
	sig := sign(secret, payload)

	if err := VerifySignature(secret, payload, sig); err != nil {
		t.Errorf("expected valid signature to pass, got error: %v", err)
	}
}

func TestVerifySignature_WrongSecret(t *testing.T) {
	payload := []byte(samplePullRequestPayload)
	sig := sign("correct-secret", payload)

	if err := VerifySignature("wrong-secret", payload, sig); err == nil {
		t.Error("expected signature verification to fail with wrong secret")
	}
}

func TestVerifySignature_TamperedPayload(t *testing.T) {
	secret := "test-secret"
	payload := []byte(samplePullRequestPayload)
	sig := sign(secret, payload)

	tampered := append([]byte{}, payload...)
	tampered[0] = 'X'

	if err := VerifySignature(secret, tampered, sig); err == nil {
		t.Error("expected signature verification to fail for tampered payload")
	}
}

func TestVerifySignature_MissingHeader(t *testing.T) {
	if err := VerifySignature("secret", []byte("{}"), ""); err == nil {
		t.Error("expected error for missing signature header")
	}
}

func TestParsePullRequestEvent(t *testing.T) {
	event, err := ParsePullRequestEvent([]byte(samplePullRequestPayload))
	if err != nil {
		t.Fatalf("ParsePullRequestEvent: %v", err)
	}

	if event.Action != "opened" {
		t.Errorf("expected action 'opened', got %q", event.Action)
	}
	if event.Number != 42 {
		t.Errorf("expected number 42, got %d", event.Number)
	}
	if event.Owner != "myorg" || event.Repo != "myrepo" {
		t.Errorf("expected myorg/myrepo, got %s/%s", event.Owner, event.Repo)
	}
	if event.HeadSHA != "abc123" {
		t.Errorf("expected head SHA abc123, got %s", event.HeadSHA)
	}
	if event.BaseSHA != "def456" {
		t.Errorf("expected base SHA def456, got %s", event.BaseSHA)
	}
}

func TestParsePullRequestEvent_MissingRepository(t *testing.T) {
	_, err := ParsePullRequestEvent([]byte(`{"action": "opened", "pull_request": {"head": {"sha": "x"}}}`))
	if err == nil {
		t.Error("expected error for payload missing repository info")
	}
}

func TestWebhookHandler_ValidPullRequestOpened(t *testing.T) {
	secret := "test-secret"
	payload := []byte(samplePullRequestPayload)
	sig := sign(secret, payload)

	var received *PullRequestEvent
	handler := WebhookHandler(secret, func(event *PullRequestEvent) error {
		received = event
		return nil
	})

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
	req.Header.Set("X-Hub-Signature-256", sig)
	req.Header.Set("X-GitHub-Event", "pull_request")

	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if received == nil {
		t.Fatal("expected onEvent to be called")
	}
	if received.HeadSHA != "abc123" {
		t.Errorf("expected head SHA abc123, got %s", received.HeadSHA)
	}
}

func TestWebhookHandler_RejectsInvalidSignature(t *testing.T) {
	handler := WebhookHandler("test-secret", func(event *PullRequestEvent) error {
		t.Fatal("onEvent should not be called for an invalid signature")
		return nil
	})

	payload := []byte(samplePullRequestPayload)
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
	req.Header.Set("X-Hub-Signature-256", "sha256=deadbeef")
	req.Header.Set("X-GitHub-Event", "pull_request")

	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestWebhookHandler_IgnoresNonPullRequestEvents(t *testing.T) {
	secret := "test-secret"
	payload := []byte(`{"zen": "Keep it logically awesome."}`)
	sig := sign(secret, payload)

	handler := WebhookHandler(secret, func(event *PullRequestEvent) error {
		t.Fatal("onEvent should not be called for a non-pull_request event")
		return nil
	})

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
	req.Header.Set("X-Hub-Signature-256", sig)
	req.Header.Set("X-GitHub-Event", "ping")

	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 (acknowledged, ignored), got %d", rec.Code)
	}
}

func TestWebhookHandler_IgnoresNonTriggerActions(t *testing.T) {
	secret := "test-secret"
	payload := []byte(`{
		"action": "closed",
		"number": 1,
		"pull_request": {"head": {"sha": "abc"}, "base": {"sha": "def"}},
		"repository": {"name": "myrepo", "owner": {"login": "myorg"}}
	}`)
	sig := sign(secret, payload)

	handler := WebhookHandler(secret, func(event *PullRequestEvent) error {
		t.Fatal("onEvent should not be called for a 'closed' action")
		return nil
	})

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
	req.Header.Set("X-Hub-Signature-256", sig)
	req.Header.Set("X-GitHub-Event", "pull_request")

	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}
