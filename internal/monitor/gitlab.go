package monitor

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
)

const gitlabAPIBase = "https://gitlab.com/api/v4"

type gitlabClient struct {
	repo   string
	token  string
	secret string
	http   *http.Client
}

func newGitLabClient(repo, token, secret string) *gitlabClient {
	return &gitlabClient{
		repo:   repo,
		token:  token,
		secret: secret,
		http: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return fmt.Errorf("refusing HTTP redirect (credential protection)")
			},
		},
	}
}

// encodedRepo returns the URL-encoded "namespace%2Frepo" form required by
// the GitLab project API when the project ID is passed as a path segment.
func (c *gitlabClient) encodedRepo() string {
	return url.PathEscape(c.repo)
}

func (c *gitlabClient) GetBranchSHA(branch string) (string, error) {
	apiURL := fmt.Sprintf("%s/projects/%s/repository/branches/%s",
		gitlabAPIBase, c.encodedRepo(), url.PathEscape(branch))

	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return "", err
	}
	// GitLab uses PRIVATE-TOKEN header — never embed in URL.
	req.Header.Set("PRIVATE-TOKEN", c.token)
	req.Header.Set("User-Agent", "drogonsec-monitor/0.1")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("GitLab API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return "", fmt.Errorf("GitLab token rejected (401) — check GITLAB_TOKEN scope (needs read_repository)")
	}
	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("branch %q not found in %s (404)", branch, c.repo)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitLab API error: %s", resp.Status)
	}

	var result struct {
		Commit struct {
			ID string `json:"id"`
		} `json:"commit"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return "", fmt.Errorf("unexpected GitLab API response: %w", err)
	}
	if result.Commit.ID == "" {
		return "", fmt.Errorf("GitLab API returned empty commit ID")
	}
	return result.Commit.ID, nil
}

// CloneAuth supplies the token to go-git directly. Embedding it in the URL
// instead would put it in the clone's .git/config on disk, since that is where
// git records the remote it was cloned from.
func (c *gitlabClient) CloneAuth() transport.AuthMethod {
	return &githttp.BasicAuth{Username: "oauth2", Password: c.token}
}

func (c *gitlabClient) CloneURL() string {
	return fmt.Sprintf("https://gitlab.com/%s.git", c.repo)
}

// ValidateWebhookSignature validates the X-Gitlab-Token header.
// GitLab uses a plain shared secret (not HMAC), so we compare with
// constant-time equality to prevent timing attacks.
func (c *gitlabClient) ValidateWebhookSignature(_ []byte, token string) error {
	if c.secret == "" {
		return fmt.Errorf("webhook secret not configured (set WEBHOOK_SECRET)")
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(c.secret)) != 1 {
		return fmt.Errorf("invalid X-Gitlab-Token — possible spoofed webhook")
	}
	return nil
}

type gitlabPushPayload struct {
	Ref string `json:"ref"` // "refs/heads/develop"
}

func (c *gitlabClient) ParsePushBranch(payload []byte) (string, error) {
	var p gitlabPushPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return "", fmt.Errorf("invalid JSON payload: %w", err)
	}
	if !strings.HasPrefix(p.Ref, "refs/heads/") {
		return "", fmt.Errorf("not a branch push event (ref: %q)", p.Ref)
	}
	branch := strings.TrimPrefix(p.Ref, "refs/heads/")
	if err := ValidateBranchName(branch); err != nil {
		return "", fmt.Errorf("webhook payload contains invalid branch name: %w", err)
	}
	return branch, nil
}
