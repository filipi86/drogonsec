package monitor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/fatih/color"
)

const (
	// maxPayloadBytes caps webhook body reads to prevent memory exhaustion.
	maxPayloadBytes = 25 * 1024 * 1024 // 25 MB
	// rateLimitCap is the max number of webhook requests accepted per minute.
	rateLimitCap = 60
)

type webhookServer struct {
	cfg    *Config
	client PlatformClient
	scanFn func(branch string) error
	mux    *http.ServeMux
	rl     *tokenBucket
}

func newWebhookServer(cfg *Config, client PlatformClient, scanFn func(string) error) *webhookServer {
	s := &webhookServer{
		cfg:    cfg,
		client: client,
		scanFn: scanFn,
		mux:    http.NewServeMux(),
		rl:     newTokenBucket(rateLimitCap, time.Minute),
	}
	s.mux.HandleFunc("/webhook", s.handleWebhook)
	s.mux.HandleFunc("/health", s.handleHealth)
	return s
}

// Start blocks until ctx is cancelled or the server exits.
func (s *webhookServer) Start(ctx context.Context) error {
	srv := &http.Server{
		Addr:    s.cfg.ListenAddr,
		Handler: s.mux,
		// Tight timeouts protect against slow-loris and resource exhaustion.
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   15 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 64 * 1024,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	tls := s.cfg.TLSCertFile != "" && s.cfg.TLSKeyFile != ""
	scheme := "http"
	if tls {
		scheme = "https"
	}
	fmt.Printf("  %s Webhook server listening on %s://%s/webhook\n",
		color.CyanString("→"), scheme, s.cfg.ListenAddr)
	if !tls {
		fmt.Printf("  %s TLS not configured — use --tls-cert / --tls-key in production\n",
			color.YellowString("⚠"))
	}

	if tls {
		return srv.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
	}
	return srv.ListenAndServe()
}

func (s *webhookServer) handleWebhook(w http.ResponseWriter, r *http.Request) {
	// 1. Rate limit — defend against webhook flooding.
	if !s.rl.Allow() {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// 2. Only accept POST.
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 3. Read body with a hard cap to prevent memory exhaustion.
	body, err := io.ReadAll(io.LimitReader(r.Body, maxPayloadBytes))
	if err != nil {
		http.Error(w, "error reading request body", http.StatusBadRequest)
		return
	}

	// 4. Validate platform-specific signature BEFORE processing any payload data.
	var sig string
	switch s.cfg.Platform {
	case PlatformGitHub:
		sig = r.Header.Get("X-Hub-Signature-256")
	case PlatformGitLab:
		sig = r.Header.Get("X-Gitlab-Token")
	}
	if err := s.client.ValidateWebhookSignature(body, sig); err != nil {
		// Fixed sleep prevents timing oracles on the rejection path.
		time.Sleep(100 * time.Millisecond)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// 5. Parse the pushed branch from the verified payload.
	branch, err := s.client.ParsePushBranch(body)
	if err != nil {
		// Unknown event type (tag push, PR, etc.) — acknowledge silently.
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// 6. Only trigger scans for the configured target branch.
	if branch != s.cfg.Branch {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// 7. Accept immediately, run scan in background.
	w.WriteHeader(http.StatusAccepted)

	go func() {
		// A panic inside scanFn must not crash the webhook server — the
		// server is long-lived and may receive many events concurrently.
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("  %s Scan panic on branch %q: %v\n",
					color.RedString("✗"), branch, r)
			}
		}()
		if err := s.scanFn(branch); err != nil {
			fmt.Printf("  %s Scan error on branch %q: %v\n",
				color.RedString("✗"), branch, err)
		}
	}()
}

func (s *webhookServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(`{"status":"ok","service":"drogonsec-monitor"}`))
}
