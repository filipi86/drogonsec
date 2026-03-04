package sca

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/drogonsec/drogonsec/internal/config"
)

const (
	osvBatchURL = "https://api.osv.dev/v1/querybatch"
	osvBatchMax = 1000 // OSV API batch limit
)

// OSV ecosystem mapping from our ecosystem names to OSV ecosystem names
var osvEcosystemMap = map[string]string{
	"npm":      "npm",
	"pip":      "PyPI",
	"maven":    "Maven",
	"go":       "Go",
	"composer": "Packagist",
	"rubygems": "RubyGems",
	"pub":      "Pub",
	"cargo":    "crates.io",
	"nuget":    "NuGet",
}

// ---- OSV API Request Types ----

type osvQuery struct {
	Version string     `json:"version"`
	Package osvPackage `json:"package"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

// ---- OSV API Response Types ----

type osvBatchResponse struct {
	Results []osvQueryResult `json:"results"`
}

type osvQueryResult struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID       string        `json:"id"`
	Aliases  []string      `json:"aliases"`
	Summary  string        `json:"summary"`
	Details  string        `json:"details"`
	Severity []osvSeverity `json:"severity"`
	Affected []osvAffected `json:"affected"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package  osvPackage `json:"package"`
	Ranges   []osvRange `json:"ranges"`
	Versions []string   `json:"versions"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// ---- OSV Client ----

type osvClient struct {
	http *http.Client
}

func newOSVClient() *osvClient {
	return &osvClient{
		http: &http.Client{Timeout: 30 * time.Second},
	}
}

// QueryBatch sends a batch query to the OSV API for a list of dependencies
// Returns a slice of findings (one per vulnerable dep found)
func (c *osvClient) QueryBatch(deps []Dependency) ([]Finding, error) {
	if len(deps) == 0 {
		return nil, nil
	}

	var allFindings []Finding

	// Process in batches of osvBatchMax
	for i := 0; i < len(deps); i += osvBatchMax {
		end := i + osvBatchMax
		if end > len(deps) {
			end = len(deps)
		}
		batch := deps[i:end]

		findings, err := c.queryBatch(batch)
		if err != nil {
			return allFindings, fmt.Errorf("OSV batch query failed: %w", err)
		}
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

func (c *osvClient) queryBatch(deps []Dependency) ([]Finding, error) {
	queries := make([]osvQuery, 0, len(deps))
	for _, dep := range deps {
		eco := osvEcosystemMap[strings.ToLower(dep.Ecosystem)]
		if eco == "" {
			continue // skip unknown ecosystems
		}
		queries = append(queries, osvQuery{
			Version: dep.Version,
			Package: osvPackage{Name: dep.Name, Ecosystem: eco},
		})
	}

	if len(queries) == 0 {
		return nil, nil
	}

	body, err := json.Marshal(osvBatchRequest{Queries: queries})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", osvBatchURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OSV API unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OSV API returned %d: %s", resp.StatusCode, string(b))
	}

	var result osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("OSV API response decode error: %w", err)
	}

	var findings []Finding
	for idx, qr := range result.Results {
		if idx >= len(deps) {
			break
		}
		dep := deps[idx]
		for _, vuln := range qr.Vulns {
			findings = append(findings, osvVulnToFinding(vuln, dep))
		}
	}

	return findings, nil
}

// osvVulnToFinding converts an OSV vulnerability to our Finding type
func osvVulnToFinding(v osvVuln, dep Dependency) Finding {
	// Extract CVE alias (prefer CVE- prefix)
	cve := v.ID
	for _, alias := range v.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			cve = alias
			break
		}
	}

	// Extract fixed version from ranges
	fixedVersion := extractFixedVersion(v.Affected)

	// Determine severity from CVSS score
	severity, cvss := parseCVSS(v.Severity)

	// Summary: prefer the shorter summary, fall back to truncated details
	desc := v.Summary
	if desc == "" && len(v.Details) > 0 {
		if len(v.Details) > 200 {
			desc = v.Details[:200] + "..."
		} else {
			desc = v.Details
		}
	}

	return Finding{
		PackageName:    dep.Name,
		PackageVersion: dep.Version,
		FixedVersion:   fixedVersion,
		Ecosystem:      dep.Ecosystem,
		ManifestFile:   dep.File,
		Severity:       severity,
		CVE:            cve,
		CVSS:           cvss,
		Description:    desc,
		Advisory:       fmt.Sprintf("https://osv.dev/vulnerability/%s", v.ID),
		OWASP:          config.OWASP_A03_SoftwareSupplyChainFailures,
	}
}

// extractFixedVersion searches affected ranges for the first "fixed" event
func extractFixedVersion(affected []osvAffected) string {
	for _, a := range affected {
		for _, r := range a.Ranges {
			for _, ev := range r.Events {
				if ev.Fixed != "" {
					return ev.Fixed
				}
			}
		}
	}
	return ""
}

// parseCVSS extracts severity and CVSS score from OSV severity entries
// Supports CVSS_V3 and CVSS_V2 score strings
func parseCVSS(severities []osvSeverity) (config.Severity, float64) {
	for _, s := range severities {
		if s.Type == "CVSS_V3" || s.Type == "CVSS_V2" {
			score := parseCVSSScore(s.Score)
			return cvssToSeverity(score), score
		}
	}
	// No score available — default to HIGH (it's a vuln after all)
	return config.SeverityHigh, 0
}

// parseCVSSScore extracts the numeric score from a CVSS vector string
// e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" → 9.8
// OSV sometimes returns just the base score as a float string too
func parseCVSSScore(score string) float64 {
	// Try direct float parse first
	var f float64
	if _, err := fmt.Sscanf(score, "%f", &f); err == nil && f > 0 && f <= 10.0 {
		return f
	}

	// Try to find score in CVSS vector (not directly available in vector string)
	// OSV sometimes provides just the vector, not the numeric score
	// In that case we estimate from the vector components
	// AV:N/AC:L/PR:N/UI:N → typically Critical/High
	upperScore := strings.ToUpper(score)
	if strings.Contains(upperScore, "AV:N") && strings.Contains(upperScore, "AC:L") &&
		strings.Contains(upperScore, "PR:N") {
		return 9.0
	}
	if strings.Contains(upperScore, "AV:N") {
		return 7.5
	}
	return 5.0
}

// cvssToSeverity maps a CVSS score to our severity levels
func cvssToSeverity(score float64) config.Severity {
	switch {
	case score >= 9.0:
		return config.SeverityCritical
	case score >= 7.0:
		return config.SeverityHigh
	case score >= 4.0:
		return config.SeverityMedium
	case score > 0:
		return config.SeverityLow
	default:
		return config.SeverityHigh // default if score unknown
	}
}
