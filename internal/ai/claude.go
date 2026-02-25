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
	anthropicAPIURL = "https://api.anthropic.com/v1/messages"
	model           = "claude-sonnet-4-20250514"
	maxTokens       = 1024
)

// Client handles Claude AI API communication
type Client struct {
	apiKey     string
	httpClient *http.Client
}

// New creates a new Claude AI client
func New(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// anthropicRequest mirrors the Anthropic API request structure
type anthropicRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	System    string    `json:"system"`
	Messages  []message `json:"messages"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// EnrichWithRemediation calls Claude AI to get remediation suggestions for findings
func (c *Client) EnrichWithRemediation(findings []analyzer.Finding) []analyzer.Finding {
	enriched := make([]analyzer.Finding, len(findings))
	copy(enriched, findings)

	// Process only high/critical findings to reduce API calls
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

// getRemediation fetches an AI-powered remediation for a single finding
func (c *Client) getRemediation(f analyzer.Finding) (string, error) {
	prompt := buildPrompt(f)

	reqBody := anthropicRequest{
		Model:     model,
		MaxTokens: maxTokens,
		System: `You are a senior security engineer expert in application security and secure coding.
Your role is to provide concise, actionable remediation advice for security vulnerabilities.
Always provide:
1. A brief explanation of why this is dangerous
2. A specific code fix (with language-appropriate examples)
3. Additional security hardening recommendations

Be concise but complete. Focus on practical fixes a developer can implement immediately.`,
		Messages: []message{
			{Role: "user", Content: prompt},
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal error: %w", err)
	}

	req, err := http.NewRequest("POST", anthropicAPIURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("request creation error: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("API call failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response error: %w", err)
	}

	var apiResp anthropicResponse
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

// buildPrompt constructs a detailed prompt for Claude
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

// GetLeakRemediation provides AI guidance for a detected secret leak
func (c *Client) GetLeakRemediation(leakType, file string) (string, error) {
	prompt := fmt.Sprintf(`A %s was detected in the file: %s

Please provide:
1. The immediate steps to take (rotate/revoke the secret)
2. How to properly manage this type of secret going forward
3. How to prevent this from happening again in CI/CD

Be concise and actionable.`, leakType, file)

	reqBody := anthropicRequest{
		Model:     model,
		MaxTokens: 512,
		System:    "You are a security expert helping developers handle exposed secrets safely and quickly.",
		Messages:  []message{{Role: "user", Content: prompt}},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", anthropicAPIURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var apiResp anthropicResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return "", err
	}

	if apiResp.Error != nil {
		return "", fmt.Errorf("%s: %s", apiResp.Error.Type, apiResp.Error.Message)
	}

	if len(apiResp.Content) == 0 {
		return "", fmt.Errorf("empty response")
	}

	return apiResp.Content[0].Text, nil
}
