package monitor

import "github.com/go-git/go-git/v5/plumbing/transport"

// PlatformClient abstracts GitHub and GitLab operations behind a single
// interface so the webhook server and poller are platform-agnostic.
type PlatformClient interface {
	// GetBranchSHA returns the current HEAD commit SHA of the given branch.
	// Used by the poller to detect new pushes without cloning.
	GetBranchSHA(branch string) (string, error)

	// CloneURL returns the HTTPS URL to clone. It carries no credentials:
	// git writes the remote URL into the clone's .git/config, so a token
	// embedded here would be written to disk in plaintext.
	CloneURL() string

	// CloneAuth returns the credentials for the clone, supplied out of band
	// so they stay in memory.
	CloneAuth() transport.AuthMethod

	// ValidateWebhookSignature verifies the platform-specific integrity
	// signature on the raw request body:
	//   GitHub  — HMAC-SHA256 in X-Hub-Signature-256 (hex-encoded)
	//   GitLab  — shared secret token in X-Gitlab-Token
	// Implementations MUST use constant-time comparison.
	ValidateWebhookSignature(payload []byte, signature string) error

	// ParsePushBranch extracts the pushed branch name from a webhook payload.
	// Returns an error (not a branch) for non-push events so callers can
	// silently acknowledge them with 204.
	ParsePushBranch(payload []byte) (string, error)
}
