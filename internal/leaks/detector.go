package leaks

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/drogonsec/drogonsec/internal/config"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// LeakFinding mirrors analyzer.LeakFinding to avoid import cycle
type LeakFinding struct {
	Type         string
	File         string
	Line         int
	Match        string
	RuleID       string
	Severity     config.Severity
	Description  string
	Entropy      float64
	InGitHistory bool
	CommitHash   string
}

// LeakRule defines a secret detection rule
type LeakRule struct {
	ID          string
	Name        string
	Pattern     *regexp.Regexp
	Severity    config.Severity
	Description string
	Confidence  string // HIGH, MEDIUM, LOW
}

// Detector handles secret and credential leak detection
type Detector struct {
	rules []LeakRule
}

// NewDetector creates a new Detector with all built-in patterns
func NewDetector() *Detector {
	d := &Detector{}
	d.loadRules()
	return d
}

// ScanFile scans a single file for secrets
func (d *Detector) ScanFile(filePath string) ([]LeakFinding, error) {
	// Skip binary files and very large files
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}
	if info.Size() > 5*1024*1024 { // skip files > 5MB
		return nil, nil
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Skip binary content
	if isBinary(content) {
		return nil, nil
	}

	var findings []LeakFinding
	lines := strings.Split(string(content), "\n")

	for lineNum, line := range lines {
		// Skip empty lines and comments (simple heuristic)
		trimmed := strings.TrimSpace(line)
		if len(trimmed) == 0 || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Guard against ReDoS: skip lines that are unreasonably long.
		// Legitimate secrets never exceed 10 000 chars; minified/binary
		// content can cause catastrophic backtracking on complex regexes.
		if len(line) > 10000 {
			continue
		}

		for _, rule := range d.rules {
			if rule.Pattern.MatchString(line) {
				match := rule.Pattern.FindString(line)
				redacted := redactSecret(match)

				entropy := 0.0
				if strings.Contains(rule.Name, "Generic") || strings.Contains(rule.Name, "High Entropy") {
					entropy = shannonEntropy(match)
					if entropy < 3.5 {
						continue // skip low entropy matches (likely false positives)
					}
				}

				findings = append(findings, LeakFinding{
					Type:        rule.Name,
					File:        filePath,
					Line:        lineNum + 1,
					Match:       redacted,
					RuleID:      rule.ID,
					Severity:    rule.Severity,
					Description: rule.Description,
					Entropy:     entropy,
				})
			}
		}
	}

	return findings, nil
}

// ScanGitHistory scans git commit history for secrets using go-git
func (d *Detector) ScanGitHistory(repoPath string) ([]LeakFinding, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, fmt.Errorf("not a git repository: %w", err)
	}

	iter, err := repo.CommitObjects()
	if err != nil {
		return nil, fmt.Errorf("cannot read commits: %w", err)
	}

	// Track seen (commit+file+line) to avoid duplicate findings
	seen := make(map[string]bool)
	var findings []LeakFinding

	err = iter.ForEach(func(c *object.Commit) error {
		tree, err := c.Tree()
		if err != nil {
			return nil // skip this commit on error
		}

		return tree.Files().ForEach(func(f *object.File) error {
			// Skip binary and large files
			if f.Size > 1*1024*1024 { // 1MB limit for git history
				return nil
			}

			if shouldSkip(f.Name) {
				return nil
			}

			reader, err := f.Reader()
			if err != nil {
				return nil
			}
			defer reader.Close()

			content, err := io.ReadAll(reader)
			if err != nil {
				return nil
			}

			if isBinary(content) {
				return nil
			}

			lines := strings.Split(string(content), "\n")
			for lineNum, line := range lines {
				trimmed := strings.TrimSpace(line)
				if len(trimmed) == 0 || strings.HasPrefix(trimmed, "#") {
					continue
				}
				if len(line) > 10000 {
					continue
				}

				for _, rule := range d.rules {
					if rule.Pattern.MatchString(line) {
						match := rule.Pattern.FindString(line)

						// Dedup key: rule + file + line content hash
						key := fmt.Sprintf("%s:%s:%d:%s", rule.ID, f.Name, lineNum, match[:min(len(match), 20)])
						if seen[key] {
							continue
						}
						seen[key] = true

						entropy := 0.0
						if strings.Contains(rule.Name, "Generic") || strings.Contains(rule.Name, "High Entropy") {
							entropy = shannonEntropy(match)
							if entropy < 3.5 {
								continue
							}
						}

						findings = append(findings, LeakFinding{
							Type:         rule.Name,
							File:         f.Name,
							Line:         lineNum + 1,
							Match:        redactSecret(match),
							RuleID:       rule.ID,
							Severity:     rule.Severity,
							Description:  rule.Description,
							Entropy:      entropy,
							InGitHistory: true,
							CommitHash:   c.Hash.String()[:8],
						})
					}
				}
			}
			return nil
		})
	})

	if err != nil {
		return findings, nil // return what we have even on partial error
	}

	return findings, nil
}

// min returns the smaller of two ints
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// loadRules registers all leak detection patterns
func (d *Detector) loadRules() {
	d.rules = []LeakRule{
		// === AWS ===
		{
			ID:          "LEAK-001",
			Name:        "AWS Access Key ID",
			Pattern:     mustCompile(`AKIA[0-9A-Z]{16}`),
			Severity:    config.SeverityCritical,
			Confidence:  "HIGH",
			Description: "AWS Access Key ID detected. This grants programmatic access to AWS services.",
		},
		{
			ID:          "LEAK-002",
			Name:        "AWS Secret Access Key",
			Pattern:     mustCompile(`(?i)aws_secret_access_key\s*=\s*[a-zA-Z0-9/+]{40}`),
			Severity:    config.SeverityCritical,
			Confidence:  "HIGH",
			Description: "AWS Secret Access Key detected. Immediate rotation required.",
		},
		{
			ID:          "LEAK-003",
			Name:        "AWS Session Token",
			Pattern:     mustCompile(`(?i)aws_session_token\s*=\s*[a-zA-Z0-9/+=]{100,}`),
			Severity:    config.SeverityCritical,
			Confidence:  "HIGH",
			Description: "AWS Session Token detected in source code.",
		},

		// === Google Cloud ===
		{
			ID:          "LEAK-010",
			Name:        "Google API Key",
			Pattern:     mustCompile(`AIza[0-9A-Za-z\\-_]{35}`),
			Severity:    config.SeverityCritical,
			Confidence:  "HIGH",
			Description: "Google API Key detected. Can be used to access Google Cloud services.",
		},
		{
			ID:          "LEAK-011",
			Name:        "Google Service Account Key",
			Pattern:     mustCompile(`"type":\s*"service_account"`),
			Severity:    config.SeverityCritical,
			Confidence:  "HIGH",
			Description: "Google Service Account JSON key detected.",
		},
		{
			ID:          "LEAK-012",
			Name:        "Google OAuth Client Secret",
			Pattern:     mustCompile(`(?i)client_secret\s*=\s*"[a-zA-Z0-9_-]{24,}"`),
			Severity:    config.SeverityHigh,
			Confidence:  "MEDIUM",
			Description: "Google OAuth client secret found in source code.",
		},

		// === GitHub ===
		{
			ID:          "LEAK-020",
			Name:        "GitHub Personal Access Token",
			Pattern:     mustCompile(`ghp_[a-zA-Z0-9]{36}`),
			Severity:    config.SeverityCritical,
			Confidence:  "HIGH",
			Description: "GitHub Personal Access Token (classic) detected.",
		},
		{
			ID:          "LEAK-021",
			Name:        "GitHub OAuth Token",
			Pattern:     mustCompile(`gho_[a-zA-Z0-9]{36}`),
			Severity:    config.SeverityCritical,
			Confidence:  "HIGH",
			Description: "GitHub OAuth token detected.",
		},
		{
			ID:          "LEAK-022",
			Name:        "GitHub App Token",
			Pattern:     mustCompile(`(ghu|ghs|ghr)_[a-zA-Z0-9]{36}`),
			Severity:    config.SeverityCritical,
			Confidence:  "HIGH",
			Description: "GitHub App token detected.",
		},
		{
			ID:          "LEAK-023",
			Name:        "GitHub Fine-Grained Token",
			Pattern:     mustCompile(`github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}`),
			Severity:    config.SeverityCritical,
			Confidence:  "HIGH",
			Description: "GitHub fine-grained personal access token detected.",
		},

		// === Stripe ===
		{
			ID:          "LEAK-030",
			Name:        "Stripe Secret Key",
			Pattern:     mustCompile(`sk_(live|test)_[a-zA-Z0-9]{24,}`),
			Severity:    config.SeverityCritical,
			Confidence:  "HIGH",
			Description: "Stripe secret API key detected. Can be used to process payments.",
		},
		{
			ID:          "LEAK-031",
			Name:        "Stripe Restricted Key",
			Pattern:     mustCompile(`rk_(live|test)_[a-zA-Z0-9]{24,}`),
			Severity:    config.SeverityHigh,
			Confidence:  "HIGH",
			Description: "Stripe restricted key detected.",
		},

		// === Slack ===
		{
			ID:          "LEAK-040",
			Name:        "Slack Bot Token",
			Pattern:     mustCompile(`xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}`),
			Severity:    config.SeverityHigh,
			Confidence:  "HIGH",
			Description: "Slack bot token detected.",
		},
		{
			ID:          "LEAK-041",
			Name:        "Slack App Token",
			Pattern:     mustCompile(`xapp-[0-9]-[A-Z0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{64}`),
			Severity:    config.SeverityHigh,
			Confidence:  "HIGH",
			Description: "Slack app-level token detected.",
		},
		{
			ID:          "LEAK-042",
			Name:        "Slack Webhook URL",
			Pattern:     mustCompile(`hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[a-zA-Z0-9]+`),
			Severity:    config.SeverityMedium,
			Confidence:  "HIGH",
			Description: "Slack incoming webhook URL found. Can be used to post messages.",
		},

		// === Twilio ===
		{
			ID:          "LEAK-050",
			Name:        "Twilio Auth Token",
			Pattern:     mustCompile(`(?i)twilio.*[a-f0-9]{32}`),
			Severity:    config.SeverityHigh,
			Confidence:  "MEDIUM",
			Description: "Potential Twilio auth token detected.",
		},

		// === SendGrid ===
		{
			ID:          "LEAK-060",
			Name:        "SendGrid API Key",
			Pattern:     mustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`),
			Severity:    config.SeverityCritical,
			Confidence:  "HIGH",
			Description: "SendGrid API key detected.",
		},

		// === Azure ===
		{
			ID:          "LEAK-070",
			Name:        "Azure Storage Account Key",
			Pattern:     mustCompile(`(?i)AccountKey=[a-zA-Z0-9+/]{86}==`),
			Severity:    config.SeverityCritical,
			Confidence:  "HIGH",
			Description: "Azure Storage Account Key detected.",
		},
		{
			ID:          "LEAK-071",
			Name:        "Azure Connection String",
			Pattern:     mustCompile(`(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=`),
			Severity:    config.SeverityCritical,
			Confidence:  "HIGH",
			Description: "Azure connection string with credentials detected.",
		},

		// === SSH / Private Keys ===
		{
			ID:          "LEAK-080",
			Name:        "RSA Private Key",
			Pattern:     mustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
			Severity:    config.SeverityCritical,
			Confidence:  "HIGH",
			Description: "RSA private key detected in source code.",
		},
		{
			ID:          "LEAK-081",
			Name:        "EC Private Key",
			Pattern:     mustCompile(`-----BEGIN EC PRIVATE KEY-----`),
			Severity:    config.SeverityCritical,
			Confidence:  "HIGH",
			Description: "EC (Elliptic Curve) private key detected.",
		},
		{
			ID:          "LEAK-082",
			Name:        "OpenSSH Private Key",
			Pattern:     mustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`),
			Severity:    config.SeverityCritical,
			Confidence:  "HIGH",
			Description: "OpenSSH private key detected.",
		},
		{
			ID:          "LEAK-083",
			Name:        "PGP Private Key",
			Pattern:     mustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
			Severity:    config.SeverityCritical,
			Confidence:  "HIGH",
			Description: "PGP private key block detected.",
		},
		{
			ID:          "LEAK-084",
			Name:        "DSA Private Key",
			Pattern:     mustCompile(`-----BEGIN DSA PRIVATE KEY-----`),
			Severity:    config.SeverityCritical,
			Confidence:  "HIGH",
			Description: "DSA private key detected.",
		},

		// === Certificates ===
		{
			ID:          "LEAK-090",
			Name:        "PKCS12 Certificate",
			Pattern:     mustCompile(`-----BEGIN CERTIFICATE-----`),
			Severity:    config.SeverityHigh,
			Confidence:  "MEDIUM",
			Description: "Certificate detected in source code.",
		},

		// === JWT ===
		{
			ID:          "LEAK-100",
			Name:        "JSON Web Token (JWT)",
			Pattern:     mustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
			Severity:    config.SeverityHigh,
			Confidence:  "HIGH",
			Description: "JWT token detected. May expose user session or contain sensitive claims.",
		},

		// === Database Connections ===
		{
			ID:          "LEAK-110",
			Name:        "Database Connection String with Password",
			Pattern:     mustCompile(`(?i)(postgres|mysql|mongodb|sqlserver|redis|mssql)://[^:]+:[^@]{4,}@`),
			Severity:    config.SeverityCritical,
			Confidence:  "HIGH",
			Description: "Database connection string with credentials detected.",
		},
		{
			ID:          "LEAK-111",
			Name:        "MongoDB Connection String",
			Pattern:     mustCompile(`mongodb(\+srv)?://[^:]+:[^@]+@[^/]+`),
			Severity:    config.SeverityCritical,
			Confidence:  "HIGH",
			Description: "MongoDB connection string with credentials detected.",
		},

		// === Generic Password Patterns ===
		{
			ID:          "LEAK-120",
			Name:        "Hardcoded Password",
			Pattern:     mustCompile(`(?i)(password|passwd|pwd|pass)\s*[:=]\s*["'][^"']{4,}["']`),
			Severity:    config.SeverityHigh,
			Confidence:  "MEDIUM",
			Description: "Hardcoded password detected. Should be stored in a secrets manager.",
		},
		{
			ID:          "LEAK-121",
			Name:        "Hardcoded API Key (Generic)",
			Pattern:     mustCompile(`(?i)(api_key|apikey|api-key)\s*[:=]\s*["'][a-zA-Z0-9_-]{16,}["']`),
			Severity:    config.SeverityHigh,
			Confidence:  "MEDIUM",
			Description: "Generic API key pattern detected in source code.",
		},
		{
			ID:          "LEAK-122",
			Name:        "Hardcoded Secret (Generic)",
			Pattern:     mustCompile(`(?i)(secret|client_secret|app_secret)\s*[:=]\s*["'][a-zA-Z0-9_-]{16,}["']`),
			Severity:    config.SeverityHigh,
			Confidence:  "MEDIUM",
			Description: "Generic secret pattern detected in source code.",
		},

		// === Environment File with Secrets ===
		{
			ID:          "LEAK-130",
			Name:        ".env file with secret",
			Pattern:     mustCompile(`(?m)^(AWS_SECRET|STRIPE_|GITHUB_TOKEN|SLACK_|TWILIO_AUTH|SENDGRID_API|DB_PASSWORD|DATABASE_URL|SECRET_KEY)=.+`),
			Severity:    config.SeverityHigh,
			Confidence:  "HIGH",
			Description: "Secret value found in environment configuration. Ensure .env files are in .gitignore.",
		},

		// === NPM / Package Registry ===
		{
			ID:          "LEAK-140",
			Name:        "NPM Auth Token",
			Pattern:     mustCompile(`//registry\.npmjs\.org/:_authToken=[a-zA-Z0-9_-]+`),
			Severity:    config.SeverityCritical,
			Confidence:  "HIGH",
			Description: "NPM authentication token found. Can be used to publish malicious packages.",
		},

		// === Docker Hub ===
		{
			ID:          "LEAK-150",
			Name:        "Docker Hub Credentials",
			Pattern:     mustCompile(`(?i)docker.*password\s*=\s*["'][^"']+["']`),
			Severity:    config.SeverityHigh,
			Confidence:  "MEDIUM",
			Description: "Docker Hub credentials detected.",
		},

		// === Terraform ===
		{
			ID:          "LEAK-160",
			Name:        "Terraform .tfstate with sensitive data",
			Pattern:     mustCompile(`"sensitive":\s*true`),
			Severity:    config.SeverityMedium,
			Confidence:  "MEDIUM",
			Description: "Terraform state file with sensitive values. Never commit .tfstate to VCS.",
		},
	}
}

// mustCompile compiles a regex or returns never-matching pattern
func mustCompile(pattern string) *regexp.Regexp {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return regexp.MustCompile(`$^`)
	}
	return re
}

// shannonEntropy calculates the Shannon entropy of a string
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// redactSecret redacts the middle portion of a secret for safe display
func redactSecret(s string) string {
	if len(s) <= 8 {
		return "***REDACTED***"
	}
	prefix := s[:4]
	suffix := s[len(s)-4:]
	return fmt.Sprintf("%s...%s [REDACTED]", prefix, suffix)
}

// isBinary checks if content appears to be a binary file
func isBinary(content []byte) bool {
	if len(content) == 0 {
		return false
	}
	// Check first 8000 bytes for null bytes (binary indicator)
	checkLen := 8000
	if len(content) < checkLen {
		checkLen = len(content)
	}
	for _, b := range content[:checkLen] {
		if b == 0 {
			return true
		}
	}
	return false
}

// GetFileExtensionIgnoreList returns extensions that should be skipped for leak scanning
func GetFileExtensionIgnoreList() []string {
	return []string{
		".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
		".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav",
		".zip", ".tar", ".gz", ".rar", ".7z",
		".pdf", ".doc", ".docx", ".xls", ".xlsx",
		".exe", ".dll", ".so", ".dylib",
		".class", ".jar", ".war",
		".lock",
	}
}

// shouldSkip returns true if a file path should be skipped
func shouldSkip(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	skipList := GetFileExtensionIgnoreList()
	for _, skip := range skipList {
		if ext == skip {
			return true
		}
	}
	return false
}

// ScanLine scans a single line for secrets (used for testing)
func (d *Detector) ScanLine(line string) []LeakFinding {
	var findings []LeakFinding
	scanner := bufio.NewScanner(strings.NewReader(line))
	for scanner.Scan() {
		l := scanner.Text()
		for _, rule := range d.rules {
			if rule.Pattern.MatchString(l) {
				match := rule.Pattern.FindString(l)
				findings = append(findings, LeakFinding{
					Type:        rule.Name,
					Match:       redactSecret(match),
					RuleID:      rule.ID,
					Severity:    rule.Severity,
					Description: rule.Description,
				})
			}
		}
	}
	return findings
}
