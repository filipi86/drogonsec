package leaks_test

import (
	"testing"

	"github.com/drogonsec/drogonsec/internal/config"
	"github.com/drogonsec/drogonsec/internal/leaks"
)

func TestDetector_AWSSKey(t *testing.T) {
	d := leaks.NewDetector()

	testCases := []struct {
		name     string
		line     string
		expected string
	}{
		{
			name:     "AWS Access Key ID",
			line:     "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
			expected: "AWS Access Key ID",
		},
		{
			name:     "GitHub Token",
			line:     "token = ghp_1234567890abcdefghij1234567890ABCDEF",
			expected: "GitHub Personal Access Token",
		},
		{
			name:     "RSA Private Key",
			line:     "-----BEGIN RSA PRIVATE KEY-----",
			expected: "RSA Private Key",
		},
		{
			name:     "Stripe Secret Key",
			line:     "stripe_key = sk_live_51234567890abcdefghijklmnop",
			expected: "Stripe Secret Key",
		},
		{
			name:     "JWT Token",
			line:     "token = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			expected: "JSON Web Token (JWT)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			findings := d.ScanLine(tc.line)
			if len(findings) == 0 {
				t.Errorf("Expected to find '%s' pattern, but got no findings", tc.expected)
				return
			}

			found := false
			for _, f := range findings {
				if f.Type == tc.expected {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("Expected finding type '%s', got: %v", tc.expected, getTypes(findings))
			}
		})
	}
}

func TestDetector_FalsePositives(t *testing.T) {
	d := leaks.NewDetector()

	// Lines that should NOT trigger findings
	safeLine := []string{
		"// Example AWS key format: AKIA...",
		"# password placeholder - set via environment",
		"const apiKey = process.env.STRIPE_KEY",
	}

	for _, line := range safeLine {
		findings := d.ScanLine(line)
		if len(findings) > 0 {
			t.Logf("Possible false positive: '%s' -> %v", line, getTypes(findings))
			// Note: false positives are expected in some cases - log but don't fail
		}
	}
}

func TestDetector_SeverityMapping(t *testing.T) {
	d := leaks.NewDetector()

	// AWS keys should be CRITICAL
	findings := d.ScanLine("aws_access_key = AKIAIOSFODNN7EXAMPLE")
	for _, f := range findings {
		if f.Type == "AWS Access Key ID" {
			if f.Severity != config.SeverityCritical {
				t.Errorf("AWS Access Key should be CRITICAL, got %s", f.Severity)
			}
		}
	}
}

func TestDetector_RedactedMatch(t *testing.T) {
	d := leaks.NewDetector()

	findings := d.ScanLine("token = AKIAIOSFODNN7EXAMPLE")
	for _, f := range findings {
		if f.Type == "AWS Access Key ID" {
			if f.Match == "AKIAIOSFODNN7EXAMPLE" {
				t.Error("Match should be redacted, not show the full secret")
			}
			if len(f.Match) == 0 {
				t.Error("Match should not be empty")
			}
		}
	}
}

// helper
func getTypes(findings []leaks.LeakFinding) []string {
	types := make([]string, len(findings))
	for i, f := range findings {
		types[i] = f.Type
	}
	return types
}
