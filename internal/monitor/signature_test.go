package monitor

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
)

const testSecret = "s3cr3t-webhook-key"

// githubSignature produces the X-Hub-Signature-256 value GitHub would send for
// a payload signed with the given secret.
func githubSignature(t *testing.T, secret string, payload []byte) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestGitHubValidateWebhookSignatureAcceptsAGenuineSignature(t *testing.T) {
	payload := []byte(`{"ref":"refs/heads/main"}`)
	c := newGitHubClient("filipi86/drogonsec", "token", testSecret)

	if err := c.ValidateWebhookSignature(payload, githubSignature(t, testSecret, payload)); err != nil {
		t.Errorf("a correctly signed payload was rejected: %v", err)
	}
}

// TestGitHubValidateWebhookSignatureRejectsForgeries is the core authentication
// check of the webhook endpoint: everything past it is treated as coming from
// the platform.
func TestGitHubValidateWebhookSignatureRejectsForgeries(t *testing.T) {
	payload := []byte(`{"ref":"refs/heads/main"}`)
	valid := githubSignature(t, testSecret, payload)

	tests := []struct {
		name      string
		secret    string
		payload   []byte
		signature string
	}{
		{
			name:      "no secret configured",
			secret:    "",
			payload:   payload,
			signature: valid,
		},
		{
			name:      "signature computed with a different secret",
			secret:    testSecret,
			payload:   payload,
			signature: githubSignature(t, "wrong-secret", payload),
		},
		{
			name:      "payload tampered with after signing",
			secret:    testSecret,
			payload:   []byte(`{"ref":"refs/heads/attacker"}`),
			signature: valid,
		},
		{
			name:      "missing header",
			secret:    testSecret,
			payload:   payload,
			signature: "",
		},
		{
			name:      "missing sha256 prefix",
			secret:    testSecret,
			payload:   payload,
			signature: strings.TrimPrefix(valid, "sha256="),
		},
		{
			name:      "sha1 algorithm prefix",
			secret:    testSecret,
			payload:   payload,
			signature: "sha1=" + strings.TrimPrefix(valid, "sha256="),
		},
		{
			name:      "non-hexadecimal digest",
			secret:    testSecret,
			payload:   payload,
			signature: "sha256=zzzznothex",
		},
		{
			name:      "truncated digest",
			secret:    testSecret,
			payload:   payload,
			signature: valid[:20],
		},
		{
			name:      "empty digest",
			secret:    testSecret,
			payload:   payload,
			signature: "sha256=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newGitHubClient("filipi86/drogonsec", "token", tt.secret)
			if err := c.ValidateWebhookSignature(tt.payload, tt.signature); err == nil {
				t.Error("the signature was accepted; anything past this check is " +
					"trusted as coming from the platform")
			}
		})
	}
}

func TestGitLabValidateWebhookSignature(t *testing.T) {
	tests := []struct {
		name    string
		secret  string
		token   string
		wantErr bool
	}{
		{"matching token", testSecret, testSecret, false},
		{"wrong token", testSecret, "not-the-secret", true},
		{"empty token", testSecret, "", true},
		{"no secret configured", "", testSecret, true},
		{"token is a prefix of the secret", testSecret, testSecret[:5], true},
		{"token has trailing whitespace", testSecret, testSecret + " ", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newGitLabClient("group/project", "token", tt.secret)
			err := c.ValidateWebhookSignature(nil, tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateWebhookSignature(%q) error = %v, wantErr %v",
					tt.token, err, tt.wantErr)
			}
		})
	}
}

// TestParsePushBranch covers both platforms: the branch is taken from a
// payload that has been signature-verified but is still attacker-influenced
// data, so the ref has to be the expected shape and the name has to survive
// validation.
func TestParsePushBranch(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    string
		wantErr bool
	}{
		{"branch push", `{"ref":"refs/heads/main"}`, "main", false},
		{"nested branch", `{"ref":"refs/heads/feature/add-sbom"}`, "feature/add-sbom", false},
		{"tag push is not a branch", `{"ref":"refs/tags/v1.0.0"}`, "", true},
		{"missing ref", `{}`, "", true},
		{"empty ref", `{"ref":""}`, "", true},
		{"malformed json", `{"ref":`, "", true},
		{"not json at all", `<html></html>`, "", true},
		{"empty body", ``, "", true},
		{"traversal in ref", `{"ref":"refs/heads/../../../etc/passwd"}`, "", true},
		{"command injection in ref", `{"ref":"refs/heads/main;rm -rf /"}`, "", true},
		{"empty branch after prefix", `{"ref":"refs/heads/"}`, "", true},
	}

	clients := map[string]PlatformClient{
		"github": newGitHubClient("filipi86/drogonsec", "t", testSecret),
		"gitlab": newGitLabClient("group/project", "t", testSecret),
	}

	for platform, client := range clients {
		for _, tt := range tests {
			t.Run(platform+"/"+tt.name, func(t *testing.T) {
				got, err := client.ParsePushBranch([]byte(tt.payload))
				if (err != nil) != tt.wantErr {
					t.Fatalf("ParsePushBranch(%q) error = %v, wantErr %v", tt.payload, err, tt.wantErr)
				}
				if got != tt.want {
					t.Errorf("ParsePushBranch(%q) = %q, want %q", tt.payload, got, tt.want)
				}
			})
		}
	}
}

// TestCloneURLDoesNotEmbedTheToken pins where the credential travels. git
// records the remote URL in the clone's .git/config, so a token embedded in
// the URL is written to disk in plaintext and survives in the temp directory
// if the process dies before cleanup. It goes through CloneAuth instead.
func TestCloneURLDoesNotEmbedTheToken(t *testing.T) {
	const token = "ghp_supersecrettoken"

	clients := map[string]PlatformClient{
		"github": newGitHubClient("filipi86/drogonsec", token, "s"),
		"gitlab": newGitLabClient("group/project", token, "s"),
	}

	for name, c := range clients {
		t.Run(name, func(t *testing.T) {
			url := c.CloneURL()
			if strings.Contains(url, token) {
				t.Errorf("CloneURL() = %q embeds the access token", url)
			}
			if strings.Contains(url, "@") {
				t.Errorf("CloneURL() = %q carries userinfo", url)
			}
			if !strings.HasPrefix(url, "https://") {
				t.Errorf("CloneURL() = %q is not an HTTPS URL", url)
			}

			// The credential still has to reach go-git, just out of band.
			auth := c.CloneAuth()
			if auth == nil {
				t.Fatal("CloneAuth() is nil; the clone would be unauthenticated")
			}
			basic, ok := auth.(*githttp.BasicAuth)
			if !ok {
				t.Fatalf("CloneAuth() = %T, want *http.BasicAuth", auth)
			}
			if basic.Password != token {
				t.Errorf("CloneAuth() password = %q, want the token", basic.Password)
			}
		})
	}
}
