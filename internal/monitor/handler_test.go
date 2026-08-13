package monitor

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// scanRecorder captures the branches handleWebhook dispatches a scan for. The
// dispatch happens on its own goroutine, so waitFor polls with a deadline
// rather than assuming it has already run.
type scanRecorder struct {
	mu       sync.Mutex
	branches []string
}

func (r *scanRecorder) scanFn(branch string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.branches = append(r.branches, branch)
	return nil
}

func (r *scanRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.branches)
}

// waitForScan waits briefly for a scan to be dispatched, and reports whether
// one was.
func (r *scanRecorder) waitForScan() bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if r.count() > 0 {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

func newTestServer(t *testing.T, branch string) (*webhookServer, *scanRecorder) {
	t.Helper()
	rec := &scanRecorder{}
	cfg := &Config{
		Platform: PlatformGitHub,
		Repo:     "filipi86/drogonsec",
		Branch:   branch,
	}
	client := newGitHubClient(cfg.Repo, "token", testSecret)
	return newWebhookServer(cfg, client, rec.scanFn), rec
}

// postWebhook sends a signed push event for the given branch.
func postWebhook(t *testing.T, s *webhookServer, method, body, signature string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/webhook", strings.NewReader(body))
	if signature != "" {
		req.Header.Set("X-Hub-Signature-256", signature)
	}
	w := httptest.NewRecorder()
	s.handleWebhook(w, req)
	return w
}

func TestHandleWebhookAcceptsASignedPushToTheWatchedBranch(t *testing.T) {
	s, rec := newTestServer(t, "main")
	body := `{"ref":"refs/heads/main"}`

	w := postWebhook(t, s, http.MethodPost, body, githubSignature(t, testSecret, []byte(body)))

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusAccepted)
	}
	if !rec.waitForScan() {
		t.Fatal("no scan was dispatched for the watched branch")
	}
	if rec.branches[0] != "main" {
		t.Errorf("scanned branch %q, want %q", rec.branches[0], "main")
	}
}

// TestHandleWebhookRejectsUnsignedRequests is the check that keeps an
// unauthenticated caller from making the server clone and scan on demand.
func TestHandleWebhookRejectsUnsignedRequests(t *testing.T) {
	body := `{"ref":"refs/heads/main"}`

	tests := []struct {
		name      string
		signature string
	}{
		{"no signature header", ""},
		{"signature from the wrong secret", githubSignature(t, "attacker-secret", []byte(body))},
		{"garbage signature", "sha256=deadbeef"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, rec := newTestServer(t, "main")

			w := postWebhook(t, s, http.MethodPost, body, tt.signature)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
			}
			if rec.count() != 0 {
				t.Error("a scan was dispatched for an unauthenticated request")
			}
		})
	}
}

// TestHandleWebhookRejectsATamperedPayload confirms the signature covers the
// body: swapping the branch after signing must not pass.
func TestHandleWebhookRejectsATamperedPayload(t *testing.T) {
	s, rec := newTestServer(t, "main")
	signed := `{"ref":"refs/heads/main"}`
	tampered := `{"ref":"refs/heads/evil"}`

	w := postWebhook(t, s, http.MethodPost, tampered, githubSignature(t, testSecret, []byte(signed)))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if rec.count() != 0 {
		t.Error("a scan was dispatched for a tampered payload")
	}
}

func TestHandleWebhookRejectsNonPostMethods(t *testing.T) {
	body := `{"ref":"refs/heads/main"}`
	sig := githubSignature(t, testSecret, []byte(body))

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			s, rec := newTestServer(t, "main")

			w := postWebhook(t, s, method, body, sig)

			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
			}
			if rec.count() != 0 {
				t.Errorf("a scan was dispatched for a %s request", method)
			}
		})
	}
}

// TestHandleWebhookIgnoresOtherBranchesAndEvents covers the two paths that are
// acknowledged with 204: a push to a branch we do not watch, and an event that
// is not a branch push at all.
func TestHandleWebhookIgnoresOtherBranchesAndEvents(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"push to another branch", `{"ref":"refs/heads/feature/x"}`},
		{"tag push", `{"ref":"refs/tags/v1.0.0"}`},
		{"pull request event", `{"action":"opened","number":1}`},
		{"malformed json", `{"ref":`},
		{"branch name that fails validation", `{"ref":"refs/heads/../../etc"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, rec := newTestServer(t, "main")

			w := postWebhook(t, s, http.MethodPost, tt.body, githubSignature(t, testSecret, []byte(tt.body)))

			if w.Code != http.StatusNoContent {
				t.Errorf("status = %d, want %d", w.Code, http.StatusNoContent)
			}
			if rec.count() != 0 {
				t.Error("a scan was dispatched for an event that should be ignored")
			}
		})
	}
}

// TestHandleWebhookRateLimits asserts the bucket is enforced ahead of any other
// work, so a flood cannot be used to force repeated clones.
func TestHandleWebhookRateLimits(t *testing.T) {
	s, _ := newTestServer(t, "main")
	body := `{"ref":"refs/heads/main"}`
	sig := githubSignature(t, testSecret, []byte(body))

	// Drain the bucket.
	for i := 0; i < rateLimitCap; i++ {
		if w := postWebhook(t, s, http.MethodPost, body, sig); w.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d was rate limited before the bucket was empty", i+1)
		}
	}

	w := postWebhook(t, s, http.MethodPost, body, sig)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want %d once the bucket is empty", w.Code, http.StatusTooManyRequests)
	}
}

func TestHandleHealth(t *testing.T) {
	s, _ := newTestServer(t, "main")

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	s.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	// Without nosniff a browser may re-interpret the body as another type.
	if n := w.Header().Get("X-Content-Type-Options"); n != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", n)
	}
	if !strings.Contains(w.Body.String(), `"status":"ok"`) {
		t.Errorf("body = %q, want a status field", w.Body.String())
	}
}

func TestTokenBucket(t *testing.T) {
	t.Run("allows up to capacity then refuses", func(t *testing.T) {
		b := newTokenBucket(3, time.Minute)
		for i := 0; i < 3; i++ {
			if !b.Allow() {
				t.Fatalf("request %d was refused while the bucket had tokens", i+1)
			}
		}
		if b.Allow() {
			t.Error("the bucket allowed a request past its capacity")
		}
	})

	t.Run("refills after the window", func(t *testing.T) {
		b := newTokenBucket(1, 10*time.Millisecond)
		if !b.Allow() {
			t.Fatal("the first request was refused")
		}
		if b.Allow() {
			t.Fatal("the bucket allowed a second request inside the window")
		}

		time.Sleep(20 * time.Millisecond)

		if !b.Allow() {
			t.Error("the bucket did not refill after the window elapsed")
		}
	})

	t.Run("is safe under concurrent use", func(t *testing.T) {
		const capacity = 50
		b := newTokenBucket(capacity, time.Minute)

		var wg sync.WaitGroup
		var mu sync.Mutex
		allowed := 0
		for i := 0; i < capacity*4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if b.Allow() {
					mu.Lock()
					allowed++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()

		if allowed != capacity {
			t.Errorf("allowed %d requests, want exactly %d", allowed, capacity)
		}
	})
}
