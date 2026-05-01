package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/filipi86/drogonsec/internal/analyzer"
	"github.com/filipi86/drogonsec/internal/config"
)

const (
	// defaultEndpoint is the built-in AI provider endpoint.
	defaultEndpoint = "https://api.anthropic.com/v1/messages"
	// defaultModel is the default model used when none is specified.
	defaultModel = "claude-sonnet-4-6"
	// defaultProvider identifies the default AI backend.
	defaultProvider = "anthropic"

	// defaultOllamaEndpoint is the local Ollama API endpoint.
	defaultOllamaEndpoint = "http://127.0.0.1:11434/api/generate"
	// defaultOllamaModel is the recommended model for security analysis.
	defaultOllamaModel = "deepseek-coder"

	// defaultOllamaTimeout is the timeout for local inference (longer than cloud).
	defaultOllamaTimeout = 120 * time.Second
	// defaultCloudTimeout is the timeout for cloud API calls.
	defaultCloudTimeout = 30 * time.Second

	maxTokens = 1024
	// maxResponseBytes limits AI response body to prevent memory exhaustion.
	maxResponseBytes = 1 << 20 // 1 MiB
)

// ClientConfig configures the AI client.
// Users can supply their own Provider, Model and Endpoint
// to integrate any OpenAI-compatible or custom AI backend.
type ClientConfig struct {
	APIKey   string        // AI provider API key (not required for ollama)
	Provider string        // "anthropic" (default) | "openai" | "azure" | "ollama" | "custom"
	Model    string        // model name override; uses provider default when empty
	Endpoint string        // custom API endpoint; uses provider default when empty
	Timeout  time.Duration // per-request timeout; 0 = auto (30s cloud, 120s ollama)
}

// Client handles AI API communication.
type Client struct {
	cfg        ClientConfig
	httpClient *http.Client
	cacheHits  int // number of cache hits in the current session
}

// CacheHits returns the number of AI responses served from cache.
func (c *Client) CacheHits() int {
	return c.cacheHits
}

// New creates a new AI client from the given ClientConfig.
func New(cfg ClientConfig) *Client {
	if cfg.Provider == "" {
		cfg.Provider = defaultProvider
	}

	// Provider-aware defaults
	if cfg.Provider == "ollama" {
		if cfg.Model == "" {
			cfg.Model = defaultOllamaModel
		}
		if cfg.Endpoint == "" {
			cfg.Endpoint = defaultOllamaEndpoint
		}
	} else {
		if cfg.Model == "" {
			cfg.Model = defaultModel
		}
		if cfg.Endpoint == "" {
			cfg.Endpoint = defaultEndpoint
		}
	}

	// Reject plaintext HTTP to prevent API key exposure in transit.
	// Allow http:// only for actual loopback IPs (127.x, ::1) to support
	// local dev proxies and Ollama. String prefix checks are insufficient
	// because "http://localhost.attacker.com" passes HasPrefix("http://localhost").
	if !isEndpointSafe(cfg.Endpoint) {
		cfg.Endpoint = defaultEndpoint
	}

	// Resolve timeout: user override > provider default
	timeout := cfg.Timeout
	if timeout == 0 {
		if cfg.Provider == "ollama" {
			timeout = defaultOllamaTimeout
		} else {
			timeout = defaultCloudTimeout
		}
	}

	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: timeout,
			// Refuse redirects. Go's default client preserves custom auth
			// headers (x-api-key) across redirects — a 302 from a hostile or
			// misconfigured endpoint could leak credentials to a third-party
			// host. Legitimate AI providers do not redirect POST API calls.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return fmt.Errorf("refusing redirect from %s to %s (would leak credentials)", via[0].URL.Host, req.URL.Host)
			},
		},
	}
}

// isEndpointSafe returns true if the endpoint is safe to use for AI calls.
// HTTPS is always allowed. HTTP is allowed only for actual loopback addresses
// (127.x.x.x, ::1) to support local dev proxies. String prefix matching is
// intentionally avoided to prevent bypasses like "http://localhost.evil.com".
func isEndpointSafe(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme == "http" {
		host := u.Hostname() // strips port
		ip := net.ParseIP(host)
		if ip != nil && ip.IsLoopback() {
			return true
		}
	}
	return false
}

// NewFromScanConfig is a convenience constructor that builds a Client
// directly from a ScanConfig (used by the scan command).
func NewFromScanConfig(sc *config.ScanConfig) *Client {
	return New(ClientConfig{
		APIKey:   sc.AIAPIKey,
		Provider: sc.AIProvider,
		Model:    sc.AIModel,
		Endpoint: sc.AIEndpoint,
		Timeout:  sc.AITimeout,
	})
}

// ── Internal request / response types ────────────────────────────────────────

// aiRequest mirrors the Anthropic API request structure.
// Many OpenAI-compatible endpoints accept the same format.
type aiRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	System    string    `json:"system"`
	Messages  []message `json:"messages"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type aiResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// ollamaRequest is the request format for Ollama's /api/generate endpoint.
type ollamaRequest struct {
	Model   string        `json:"model"`
	Prompt  string        `json:"prompt"`
	System  string        `json:"system,omitempty"`
	Stream  bool          `json:"stream"`
	Options ollamaOptions `json:"options,omitempty"`
}

type ollamaOptions struct {
	Temperature float64 `json:"temperature,omitempty"`
	NumPredict  int     `json:"num_predict,omitempty"`
}

// ollamaResponse is the response format from Ollama's /api/generate endpoint.
type ollamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
	Error    string `json:"error,omitempty"`
}

// ── Public API ────────────────────────────────────────────────────────────────

// CheckHealth verifies that the AI backend is reachable.
// For Ollama, it hits GET /api/tags. For cloud providers, it returns nil.
func (c *Client) CheckHealth() error {
	if !c.isOllama() {
		return nil
	}
	healthURL := strings.Replace(c.cfg.Endpoint, "/api/generate", "/api/tags", 1)
	client := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("refusing redirect during health check")
		},
	}
	resp, err := client.Get(healthURL)
	if err != nil {
		return fmt.Errorf("ollama not reachable at %s: %w", healthURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ollama health check failed: HTTP %d", resp.StatusCode)
	}
	return nil
}

// EnrichWithRemediation calls the configured AI to get remediation
// suggestions for high/critical findings.
// Returns the enriched findings and the number of errors encountered.
func (c *Client) EnrichWithRemediation(findings []analyzer.Finding) ([]analyzer.Finding, int, error) {
	enriched := make([]analyzer.Finding, len(findings))
	copy(enriched, findings)

	var errCount int
	var lastErr error
	for i, f := range enriched {
		if f.Severity == config.SeverityCritical || f.Severity == config.SeverityHigh {
			suggestion, err := c.getRemediation(f)
			if err != nil {
				errCount++
				lastErr = err
				continue
			}
			if suggestion != "" {
				enriched[i].AIRemediation = suggestion
			}
		}
	}
	return enriched, errCount, lastErr
}

// GetLeakRemediation provides AI guidance for a detected secret leak.
// It checks the local cache first using leakType + file as key components.
func (c *Client) GetLeakRemediation(leakType, file string) (string, error) {
	key := cacheKey(c.cfg.Provider, c.cfg.Model, leakType, file, "")
	if cached, ok := c.getCached(key); ok {
		c.cacheHits++
		return cached, nil
	}

	prompt := fmt.Sprintf(`A %s was detected in the file: %s

Please provide:
1. The immediate steps to take (rotate/revoke the secret)
2. How to properly manage this type of secret going forward
3. How to prevent this from happening again in CI/CD

Be concise and actionable.`, leakType, file)

	resp, err := c.call(prompt, "You are a security expert helping developers handle exposed secrets safely and quickly.", 512)
	if err != nil {
		return "", err
	}

	c.setCache(key, resp)
	return resp, nil
}

// GetSASTRemediation fetches AI remediation for a single SAST finding.
// It checks cache first and stores new responses.
func (c *Client) GetSASTRemediation(f analyzer.Finding) (string, error) {
	return c.getRemediation(f)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

// isOllama returns true if the configured provider is Ollama.
func (c *Client) isOllama() bool {
	return strings.ToLower(c.cfg.Provider) == "ollama"
}

// getRemediation fetches an AI-powered remediation for a single finding.
// It checks the local cache first and stores new responses for future reuse.
func (c *Client) getRemediation(f analyzer.Finding) (string, error) {
	// Build cache key from provider + model + ruleID + severity + code snippet.
	key := cacheKey(c.cfg.Provider, c.cfg.Model, f.RuleID, string(f.Severity), f.Code)
	if cached, ok := c.getCached(key); ok {
		c.cacheHits++
		return cached, nil
	}

	system := `You are a senior security engineer expert in application security and secure coding.
Your role is to provide concise, actionable remediation advice for security vulnerabilities.
Always provide:
1. A brief explanation of why this is dangerous
2. A specific code fix (with language-appropriate examples)
3. Additional security hardening recommendations

Be concise but complete. Focus on practical fixes a developer can implement immediately.`

	resp, err := c.call(buildPrompt(f), system, maxTokens)
	if err != nil {
		return "", err
	}

	c.setCache(key, resp)
	return resp, nil
}

// call sends a prompt to the configured AI endpoint and returns the text reply.
// It dispatches to the appropriate backend based on the configured provider.
func (c *Client) call(prompt, system string, tokens int) (string, error) {
	if c.isOllama() {
		return c.callOllama(prompt, system, tokens)
	}
	return c.callCloud(prompt, system, tokens)
}

// callCloud sends a request to a cloud AI provider (Anthropic, OpenAI, Azure).
func (c *Client) callCloud(prompt, system string, tokens int) (string, error) {
	reqBody := aiRequest{
		Model:     c.cfg.Model,
		MaxTokens: tokens,
		System:    system,
		Messages:  []message{{Role: "user", Content: prompt}},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal error: %w", err)
	}

	// context.Background() allows the http.Client Timeout to remain the sole
	// deadline — callers do not yet pass a context, but using
	// NewRequestWithContext makes future propagation trivial without changing
	// the call sites again.
	req, err := http.NewRequestWithContext(context.Background(), "POST", c.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("request creation error: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	c.setAuthHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("API call failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return "", fmt.Errorf("read response error: %w", err)
	}

	var apiResp aiResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return "", fmt.Errorf("unmarshal error: %w", err)
	}

	if apiResp.Error != nil {
		return "", fmt.Errorf("API error: %s - %s", apiResp.Error.Type, apiResp.Error.Message)
	}

	if len(apiResp.Content) == 0 {
		return "", fmt.Errorf("empty response from API")
	}

	return apiResp.Content[0].Text, nil
}

// callOllama sends a request to a local Ollama instance.
func (c *Client) callOllama(prompt, system string, tokens int) (string, error) {
	reqBody := ollamaRequest{
		Model:  c.cfg.Model,
		Prompt: prompt,
		System: system,
		Stream: false,
		Options: ollamaOptions{
			Temperature: 0.2, // low for precise security analysis
			NumPredict:  tokens,
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal error: %w", err)
	}

	// context.Background() mirrors the callCloud approach — the http.Client
	// Timeout is the effective deadline for local Ollama calls.
	req, err := http.NewRequestWithContext(context.Background(), "POST", c.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("request creation error: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("ollama call failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return "", fmt.Errorf("read response error: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama error: HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var ollamaResp ollamaResponse
	if err := json.Unmarshal(respBody, &ollamaResp); err != nil {
		return "", fmt.Errorf("ollama unmarshal error: %w", err)
	}

	if ollamaResp.Error != "" {
		return "", fmt.Errorf("ollama error: %s", ollamaResp.Error)
	}

	if ollamaResp.Response == "" {
		return "", fmt.Errorf("empty response from ollama")
	}

	return ollamaResp.Response, nil
}

// setAuthHeaders sets the appropriate authentication headers based on provider.
//
//   - "anthropic" (default): x-api-key + anthropic-version
//   - "openai" / "azure" / "custom": Authorization: Bearer <key>
//   - "ollama": no authentication required
func (c *Client) setAuthHeaders(req *http.Request) {
	if c.isOllama() {
		return
	}
	switch strings.ToLower(c.cfg.Provider) {
	case "openai", "azure", "custom":
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	default: // anthropic
		req.Header.Set("x-api-key", c.cfg.APIKey)
		req.Header.Set("anthropic-version", "2023-06-01")
	}
}

// buildPrompt constructs a detailed prompt for a SAST finding.
func buildPrompt(f analyzer.Finding) string {
	var sb strings.Builder

	sb.WriteString("## Security Vulnerability Found\n\n")
	fmt.Fprintf(&sb, "**Vulnerability:** %s\n", f.Title)
	fmt.Fprintf(&sb, "**Severity:** %s\n", f.Severity)
	fmt.Fprintf(&sb, "**Language:** %s\n", f.Language)
	fmt.Fprintf(&sb, "**OWASP Category:** %s\n", f.OWASP)
	fmt.Fprintf(&sb, "**CWE:** %s\n", f.CWE)
	fmt.Fprintf(&sb, "**CVSS Score:** %.1f\n\n", f.CVSS)

	if f.Code != "" {
		sb.WriteString("**Vulnerable Code:**\n```\n")
		sb.WriteString(f.Code)
		sb.WriteString("\n```\n\n")
	}

	fmt.Fprintf(&sb, "**File:** %s (line %d)\n\n", f.File, f.Line)
	sb.WriteString("Please provide:\n")
	sb.WriteString("1. Why this vulnerability is dangerous in this specific context\n")
	sb.WriteString("2. A corrected code example\n")
	sb.WriteString("3. Any additional security controls to add\n")

	return sb.String()
}
