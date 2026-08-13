package monitor

import (
	"net"
	"strings"
	"testing"
)

// TestValidateBranchNameRejectsInjection covers the values that reach this
// function from an untrusted webhook payload. The branch name is interpolated
// into API URLs and filesystem paths downstream, so anything that could break
// out of either has to be rejected here.
func TestValidateBranchNameRejectsInjection(t *testing.T) {
	tests := []struct {
		name   string
		branch string
	}{
		{"empty", ""},
		{"parent directory traversal", "../../etc/passwd"},
		{"traversal in the middle", "feature/../../etc/shadow"},
		{"bare double dot", ".."},
		{"leading slash makes it absolute", "/etc/passwd"},
		{"trailing slash", "main/"},
		{"shell command substitution", "main$(whoami)"},
		{"shell backticks", "main`id`"},
		{"shell separator", "main;rm -rf /"},
		{"pipe", "main|cat"},
		{"ampersand", "main&&id"},
		{"space", "my branch"},
		{"newline", "main\nX-Injected: 1"},
		{"carriage return", "main\r\nHost: evil"},
		{"null byte", "main\x00"},
		{"url encoded traversal", "%2e%2e%2fetc"},
		{"query string", "main?token=x"},
		{"fragment", "main#frag"},
		{"colon", "main:8080"},
		{"at sign", "main@evil.com"},
		{"tab", "main\tX"},
		{"too long", strings.Repeat("a", 256)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateBranchName(tt.branch); err == nil {
				t.Errorf("ValidateBranchName(%q) accepted the value; it reaches "+
					"URLs and filesystem paths downstream", tt.branch)
			}
		})
	}
}

func TestValidateBranchNameAcceptsRealBranches(t *testing.T) {
	valid := []string{
		"main",
		"develop",
		"feature/add-sbom",
		"release/v1.2.3",
		"fix_123",
		"user.name/topic",
		"a",
		strings.Repeat("a", 255), // exactly at the limit
	}

	for _, branch := range valid {
		if err := ValidateBranchName(branch); err != nil {
			t.Errorf("ValidateBranchName(%q) rejected a valid branch: %v", branch, err)
		}
	}
}

func TestValidateRepoSlug(t *testing.T) {
	tests := []struct {
		name    string
		repo    string
		wantErr bool
	}{
		{"plain owner/repo", "filipi86/drogonsec", false},
		{"dots dashes underscores", "my-org/my_repo.js", false},
		{"no slash", "drogonsec", true},
		{"empty", "", true},
		{"too many segments", "a/b/c", true},
		{"url injection", "owner/repo?x=1", true},
		{"absolute url", "https://evil.com/owner/repo", true},
		{"traversal", "../../etc/passwd", true},
		{"space", "owner/my repo", true},
		{"at sign for credentials", "user@host/repo", true},
		{"empty owner", "/repo", true},
		{"empty repo", "owner/", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRepoSlug(tt.repo)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRepoSlug(%q) error = %v, wantErr %v", tt.repo, err, tt.wantErr)
			}
		})
	}
}

func TestAPIHostForPlatform(t *testing.T) {
	tests := []struct {
		platform string
		want     string
		wantErr  bool
	}{
		{"github", "api.github.com", false},
		{"gitlab", "gitlab.com", false},
		{"bitbucket", "", true},
		{"", "", true},
		{"GitHub", "", true}, // the comparison is case-sensitive by design
	}

	for _, tt := range tests {
		t.Run(tt.platform, func(t *testing.T) {
			got, err := APIHostForPlatform(tt.platform)
			if (err != nil) != tt.wantErr {
				t.Fatalf("APIHostForPlatform(%q) error = %v, wantErr %v", tt.platform, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("APIHostForPlatform(%q) = %q, want %q", tt.platform, got, tt.want)
			}
		})
	}
}

// TestValidateAPIHostRejectsAnythingOffTheAllowlist is the SSRF guard: only the
// two platform API hosts may be contacted, no matter what a config or payload
// asks for.
func TestValidateAPIHostRejectsAnythingOffTheAllowlist(t *testing.T) {
	blocked := []string{
		"localhost",
		"127.0.0.1",
		"169.254.169.254", // cloud instance metadata
		"metadata.google.internal",
		"evil.com",
		"api.github.com.evil.com",
		"api.github.com:8080",
		"",
	}

	for _, host := range blocked {
		t.Run(host, func(t *testing.T) {
			if err := ValidateAPIHost(host); err == nil {
				t.Errorf("ValidateAPIHost(%q) accepted a host off the allowlist", host)
			}
		})
	}
}

func TestValidateAPIHostAcceptsPlatformHosts(t *testing.T) {
	// These resolve to public addresses; a DNS failure is tolerated by design,
	// so this asserts only that the allowlist admits them.
	for _, host := range []string{"api.github.com", "gitlab.com"} {
		if err := ValidateAPIHost(host); err != nil {
			t.Errorf("ValidateAPIHost(%q) = %v, want nil", host, err)
		}
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", true},
		{"127.0.0.1", true},
		{"169.254.169.254", true}, // AWS/GCP instance metadata
		{"::1", true},
		{"fc00::1", true},
		{"fe80::1", true},
		{"8.8.8.8", false},
		{"140.82.121.4", false}, // github.com
		{"172.32.0.1", false},   // just outside 172.16.0.0/12
		{"2606:4700::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("could not parse %q", tt.ip)
			}
			if got := isPrivateIP(ip); got != tt.want {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}
