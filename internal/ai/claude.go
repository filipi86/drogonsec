package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/drogonsec/drogonsec/internal/analyzer"
	"github.com/drogonsec/drogonsec/internal/config"
)

const (
	// defaultEndpoint is the built-in AI provider endpoint.
	defaultEndpoint = "https://api.anthropic.com/v1/messages"
	// defaultModel is the default model used when none is specified.
	defaultModel = "claude-sonnet-4-20250514"
	// defaultProvider identifies the default AI backend.
	defaultProvider = "anthropic"

	maxTokens = 1024
)

// ClientConfig configures the AI client.
// Users can supply their own Provider, Model and Endpoint
// to integrate any OpenAI-compatible or custom AI backend.
type ClientConfig struct {
	APIKey   string // AI provider API key
	Provider string // "anthropic" (default) | "openai" | "azure" | "custom"
	Model    string // model name override; uses defaultModel when empty
	Endpoint string // custom API endpoint; uses defaultEndpoint when empty
}

// Client handles AI API communication.
type Client struct {
	cfg        ClientConfig
	httpClient *http.Client
}

// New creates a new AI client from the given ClientConfig.
func New(cfg ClientConfig) *Client {
	if cfg.Provider == "" {
		cfg.Provider = defaultProvider
	}
	if cfg.Model == "" {
		cfg.Model = defaultModel
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = defaultEndpoint
	}
	// Reject plaintext HTTP to prevent API key exposure in transit.
	// Allow localhost HTTP for local development/testing only.
	if !strings.HasPrefix(cfg.Endpoint, "https://") &&
		!strings.HasPrefix(cfg.Endpoint, "http://localhost") &&
		!strings.HasPrefix(cfg.Endpoint, "http://127.0.0.1") {
		cfg.Endpoint = defaultEndpoint // silently fall back to safe default
	}
	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// NewFromScanConfig is a convenience constructor that builds a Client
// directly from a ScanConfig (used by the scan command).
func NewFromScanConfig(sc *config.ScanConfig) *Client {
	return New(ClientConfig{
		APIKey:   sc.AIAPIKey,
		Provider: sc.AIProvider,
		Model:    sc.AIModel,
		Endpoint: sc.AIEndpoint,
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

// ── Public API ────────────────────────────────────────────────────────────────

// EnrichWithRemediation calls the configured AI to get remediation
// suggestions for high/critical findings.
func (c *Client) EnrichWithRemediation(findings []analyzer.Finding) []analyzer.Finding {
	enriched := make([]analyzer.Finding, len(findings))
	copy(enriched, findings)

	for i, f := range enriched {
		if f.Severity == config.SeverityCritical || f.Severity == config.SeverityHigh {
			suggestion, err := c.getRemediation(f)
			if err == nil && suggestion != "" {
				enriched[i].AIRemediation = suggestion
			}
		}
	}
	return enriched
}

// GetLeakRemediation provides AI guidance for a detected secret leak.
func (c *Client) GetLeakRemediation(leakType, file string) (string, error) {
	prompt := fmt.Sprintf(`A %s was detected in the file: %s

Please provide:
1. The immediate steps to take (rotate/revoke the secret)
2. How to properly manage this type of secret going forward
3. How to prevent this from happening again in CI/CD

Be concise and actionable.`, leakType, file)

	return c.call(prompt, "You are a security expert helping developers handle exposed secrets safely and quickly.", 512)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

// getRemediation fetches an AI-powered remediation for a single finding.
func (c *Client) getRemediation(f analyzer.Finding) (string, error) {
	system := `You are a senior security engineer expert in application security and secure coding.
Your role is to provide concise, actionable remediation advice for security vulnerabilities.
Always provide:
1. A brief explanation of why this is dangerous
2. A specific code fix (with language-appropriate examples)
3. Additional security hardening recommendations

Be concise but complete. Focus on practical fixes a developer can implement immediately.`

	return c.call(buildPrompt(f), system, maxTokens)
}

// call sends a prompt to the configured AI endpoint and returns the text reply.
func (c *Client) call(prompt, system string, tokens int) (string, error) {
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

	req, err := http.NewRequest("POST", c.cfg.Endpoint, bytes.NewReader(body))
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

	respBody, err := io.ReadAll(resp.Body)
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

// setAuthHeaders sets the appropriate authentication headers based on provider.
//
//   - "anthropic" (default): x-api-key + anthropic-version
//   - "openai" / "azure" / "custom": Authorization: Bearer <key>
func (c *Client) setAuthHeaders(req *http.Request) {
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
	sb.WriteString(fmt.Sprintf("**Vulnerability:** %s\n", f.Title))
	sb.WriteString(fmt.Sprintf("**Severity:** %s\n", f.Severity))
	sb.WriteString(fmt.Sprintf("**Language:** %s\n", f.Language))
	sb.WriteString(fmt.Sprintf("**OWASP Category:** %s\n", f.OWASP))
	sb.WriteString(fmt.Sprintf("**CWE:** %s\n", f.CWE))
	sb.WriteString(fmt.Sprintf("**CVSS Score:** %.1f\n\n", f.CVSS))

	if f.Code != "" {
		sb.WriteString("**Vulnerable Code:**\n```\n")
		sb.WriteString(f.Code)
		sb.WriteString("\n```\n\n")
	}

	sb.WriteString(fmt.Sprintf("**File:** %s (line %d)\n\n", f.File, f.Line))
	sb.WriteString("Please provide:\n")
	sb.WriteString("1. Why this vulnerability is dangerous in this specific context\n")
	sb.WriteString("2. A corrected code example\n")
	sb.WriteString("3. Any additional security controls to add\n")

	return sb.String()
}
