package monitor

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

var (
	validBranchName = regexp.MustCompile(`^[a-zA-Z0-9._/\-]+$`)
	validRepoSlug   = regexp.MustCompile(`^[a-zA-Z0-9._\-]+/[a-zA-Z0-9._\-]+$`)
)

// ValidateBranchName rejects branch names that could cause path traversal or
// shell injection when used in API URLs or filesystem paths.
func ValidateBranchName(branch string) error {
	if branch == "" {
		return fmt.Errorf("branch name cannot be empty")
	}
	if len(branch) > 255 {
		return fmt.Errorf("branch name too long (max 255 chars)")
	}
	if !validBranchName.MatchString(branch) {
		return fmt.Errorf("invalid branch name %q: only [a-zA-Z0-9._/-] allowed", branch)
	}
	if strings.Contains(branch, "..") {
		return fmt.Errorf("branch name cannot contain '..' (path traversal)")
	}
	if strings.HasPrefix(branch, "/") || strings.HasSuffix(branch, "/") {
		return fmt.Errorf("branch name cannot start or end with '/'")
	}
	return nil
}

// ValidateRepoSlug ensures the repo is in "owner/repo" format with no URL
// injection characters.
func ValidateRepoSlug(repo string) error {
	if !validRepoSlug.MatchString(repo) {
		return fmt.Errorf("invalid repo format %q: expected owner/repo (alphanumeric, '.', '-', '_' only)", repo)
	}
	return nil
}

// allowedAPIHosts is the explicit allowlist for platform API hostnames.
// This prevents SSRF by rejecting any host not in this set.
var allowedAPIHosts = map[string]bool{
	"api.github.com": true,
	"gitlab.com":     true,
}

// APIHostForPlatform returns the canonical API hostname for a supported platform.
func APIHostForPlatform(platform string) (string, error) {
	switch platform {
	case "github":
		return "api.github.com", nil
	case "gitlab":
		return "gitlab.com", nil
	default:
		return "", fmt.Errorf("unknown platform %q", platform)
	}
}

// ValidateAPIHost blocks SSRF by verifying the resolved hostname is in the
// platform allowlist and does not resolve to a private/loopback address.
func ValidateAPIHost(host string) error {
	if !allowedAPIHosts[host] {
		return fmt.Errorf("API host %q is not in the approved platform list", host)
	}
	ips, err := net.LookupHost(host)
	if err != nil {
		// DNS failure is acceptable at startup — the actual request will fail.
		return nil
	}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip != nil && isPrivateIP(ip) {
			return fmt.Errorf("API host %q resolved to private IP %s (SSRF protection)", host, ipStr)
		}
	}
	return nil
}

// isPrivateIP returns true for RFC1918, loopback, link-local, and ULA ranges.
func isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}
