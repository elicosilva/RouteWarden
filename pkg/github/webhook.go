package github

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// PullRequestEvent is the subset of a GitHub `pull_request` webhook payload
// that RouteWarden needs to run a scan: which repo, which PR, and the head
// commit SHA to fetch file contents at (rule R5 needs a full-file fetch at
// the exact commit the PR is proposing, not just the diff).
type PullRequestEvent struct {
	Action  string
	Number  int
	Owner   string
	Repo    string
	HeadSHA string
	HeadRef string
	BaseSHA string
	BaseRef string
}

// rawPullRequestPayload mirrors only the fields of GitHub's pull_request
// webhook JSON that ParsePullRequestEvent needs.
type rawPullRequestPayload struct {
	Action      string `json:"action"`
	Number      int    `json:"number"`
	PullRequest struct {
		Head struct {
			SHA string `json:"sha"`
			Ref string `json:"ref"`
		} `json:"head"`
		Base struct {
			SHA string `json:"sha"`
			Ref string `json:"ref"`
		} `json:"base"`
	} `json:"pull_request"`
	Repository struct {
		Name  string `json:"name"`
		Owner struct {
			Login string `json:"login"`
		} `json:"owner"`
	} `json:"repository"`
}

// ScanTriggerActions are the pull_request actions RouteWarden actually
// re-scans for. Other actions (closed, labeled, review_requested, ...) are
// acknowledged with 200 but produce no scan.
var ScanTriggerActions = map[string]bool{
	"opened":      true,
	"synchronize": true,
	"reopened":    true,
}

// ParsePullRequestEvent decodes a raw pull_request webhook payload. Callers
// MUST call VerifySignature on the raw bytes before calling this — an
// unverified payload could come from anyone on the internet, not just
// GitHub.
func ParsePullRequestEvent(payload []byte) (*PullRequestEvent, error) {
	var raw rawPullRequestPayload
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("github: decode pull_request payload: %w", err)
	}

	if raw.Repository.Name == "" || raw.Repository.Owner.Login == "" {
		return nil, errors.New("github: pull_request payload missing repository owner/name")
	}
	if raw.PullRequest.Head.SHA == "" {
		return nil, errors.New("github: pull_request payload missing head.sha")
	}

	return &PullRequestEvent{
		Action:  raw.Action,
		Number:  raw.Number,
		Owner:   raw.Repository.Owner.Login,
		Repo:    raw.Repository.Name,
		HeadSHA: raw.PullRequest.Head.SHA,
		HeadRef: raw.PullRequest.Head.Ref,
		BaseSHA: raw.PullRequest.Base.SHA,
		BaseRef: raw.PullRequest.Base.Ref,
	}, nil
}

// VerifySignature checks a GitHub webhook's HMAC-SHA256 signature (the
// X-Hub-Signature-256 header, formatted "sha256=<hex>") against payload
// using secret. This must run BEFORE the payload is trusted for anything —
// parsing, scanning, or any GitHub API call.
func VerifySignature(secret string, payload []byte, signatureHeader string) error {
	const prefix = "sha256="
	if len(signatureHeader) <= len(prefix) || signatureHeader[:len(prefix)] != prefix {
		return errors.New("github: missing or malformed X-Hub-Signature-256 header")
	}

	expected, err := hex.DecodeString(signatureHeader[len(prefix):])
	if err != nil {
		return fmt.Errorf("github: malformed signature hex: %w", err)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	computed := mac.Sum(nil)

	if !hmac.Equal(computed, expected) {
		return errors.New("github: signature verification failed")
	}

	return nil
}

// WebhookHandler builds an http.HandlerFunc that verifies the incoming
// request's signature, parses it as a pull_request event, and — only for
// actions in ScanTriggerActions — invokes onEvent. Rule R1 (human-in-the-
// loop) and R7 (read-only against third parties) are enforced by what
// onEvent is allowed to do, not by this handler; this handler's only job is
// authenticated routing.
func WebhookHandler(secret string, onEvent func(event *PullRequestEvent) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		if err := VerifySignature(secret, body, r.Header.Get("X-Hub-Signature-256")); err != nil {
			http.Error(w, "signature verification failed", http.StatusUnauthorized)
			return
		}

		if r.Header.Get("X-GitHub-Event") != "pull_request" {
			// Not an error — a GitHub App receives many event types we
			// don't care about (issue_comment, check_run, ping, ...).
			// Acknowledge and move on.
			w.WriteHeader(http.StatusOK)
			return
		}

		event, err := ParsePullRequestEvent(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if !ScanTriggerActions[event.Action] {
			w.WriteHeader(http.StatusOK)
			return
		}

		if err := onEvent(event); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}
