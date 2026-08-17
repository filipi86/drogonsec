package sca

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/filipi86/drogonsec/internal/config"
)

const (
	osvBatchURL = "https://api.osv.dev/v1/querybatch"
	osvVulnURL  = "https://api.osv.dev/v1/vulns/"
	osvBatchMax = 1000 // OSV API batch limit

	// osvHydrateWorkers bounds the concurrent detail requests. The batch
	// endpoint returns identifiers only, so each advisory needs its own
	// request; this keeps a dependency-heavy project from opening hundreds of
	// connections at once against a public API.
	osvHydrateWorkers = 8

	// maxOSVResponseBytes caps any response body we read from OSV (success or
	// error) so a rogue or compromised endpoint cannot OOM the scanner by
	// streaming gigabytes. 32 MiB is ~10x the largest real batch response
	// observed.
	maxOSVResponseBytes = 32 * 1024 * 1024
)

// osvEcosystemMap translates our ecosystem names into the names OSV uses.
//
// The keys MUST cover every ecosystem string the manifest parsers in engine.go
// attach to a Dependency — an ecosystem missing from this map is skipped
// silently, and the scan then reports no vulnerabilities for an entire
// language. TestQueryBatchQueriesEveryParserEcosystem enforces that coupling.
// The package-manager aliases are kept so a caller constructing a Dependency
// by hand is not caught out by which of the two names we happened to pick.
var osvEcosystemMap = map[string]string{
	// Emitted by the parsers.
	"npm":       "npm",
	"pypi":      "PyPI",
	"maven":     "Maven",
	"go":        "Go",
	"packagist": "Packagist",
	"rubygems":  "RubyGems",
	"pub":       "Pub",

	// Package-manager aliases for the same ecosystems.
	"pip":      "PyPI",
	"composer": "Packagist",
	"gem":      "RubyGems",
	"golang":   "Go",

	// Ecosystems OSV covers that we have no parser for yet.
	"cargo": "crates.io",
	"nuget": "NuGet",
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
	// baseURL is the batch-query endpoint, and vulnURL the per-advisory detail
	// endpoint. They are fields rather than constants so tests can point the
	// client at a local server instead of reaching out to api.osv.dev.
	baseURL string
	vulnURL string
}

func newOSVClient() *osvClient {
	return &osvClient{
		http:    &http.Client{Timeout: 30 * time.Second},
		baseURL: osvBatchURL,
		vulnURL: osvVulnURL,
	}
}

// hydrate fills in the advisory details the batch endpoint does not return.
//
// /v1/querybatch answers with identifiers only — each vuln is {id, modified}
// and nothing else. Every field that makes a finding actionable (the CVE
// alias, the description, the CVSS score, and above all the fixed version)
// lives in the full record at /v1/vulns/{id}, so without this step the scanner
// reports "you have N vulnerabilities" with no severity, no explanation and no
// upgrade target.
//
// Details are fetched once per advisory, however many packages reference it,
// and a failed fetch leaves that advisory as the batch returned it rather than
// dropping the finding: a vulnerability we cannot describe is still one worth
// reporting.
func (c *osvClient) hydrate(ids []string) map[string]osvVuln {
	unique := make([]string, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		unique = append(unique, id)
	}

	details := make(map[string]osvVuln, len(unique))
	if len(unique) == 0 {
		return details
	}

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	work := make(chan string)

	workers := osvHydrateWorkers
	if len(unique) < workers {
		workers = len(unique)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range work {
				v, err := c.fetchVuln(id)
				if err != nil {
					continue // keep the identifier-only finding
				}
				mu.Lock()
				details[id] = v
				mu.Unlock()
			}
		}()
	}
	for _, id := range unique {
		work <- id
	}
	close(work)
	wg.Wait()

	return details
}

// fetchVuln retrieves one advisory's full record.
func (c *osvClient) fetchVuln(id string) (osvVuln, error) {
	var v osvVuln

	req, err := http.NewRequest("GET", c.vulnURL+url.PathEscape(id), nil)
	if err != nil {
		return v, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return v, err
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, maxOSVResponseBytes)
	if resp.StatusCode != http.StatusOK {
		return v, fmt.Errorf("OSV returned %d for %s", resp.StatusCode, id)
	}
	if err := json.NewDecoder(limited).Decode(&v); err != nil {
		return v, fmt.Errorf("decoding advisory %s: %w", id, err)
	}
	return v, nil
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
	// queried records the dependency behind each query. Dependencies whose
	// ecosystem OSV does not cover are skipped, so query i is not generally
	// deps[i] — indexing the responses straight back into deps attributes a
	// vulnerability to whichever package happens to sit at that offset.
	queried := make([]Dependency, 0, len(deps))
	for _, dep := range deps {
		eco := osvEcosystemMap[strings.ToLower(dep.Ecosystem)]
		if eco == "" {
			continue // skip unknown ecosystems
		}
		// A range is not a version. Asking OSV about the number a range starts
		// at answers a question nobody put: "^4.17.15" installs lodash 4.17.21,
		// and three of the six advisories against 4.17.15 are fixed by then.
		// The package stays in the inventory and in the SBOM; what it cannot do
		// is carry a finding.
		if dep.VersionIsRange {
			continue
		}
		queries = append(queries, osvQuery{
			Version: dep.Version,
			Package: osvPackage{Name: dep.Name, Ecosystem: eco},
		})
		queried = append(queried, dep)
	}

	if len(queries) == 0 {
		return nil, nil
	}

	body, err := json.Marshal(osvBatchRequest{Queries: queries})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", c.baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OSV API unreachable: %w", err)
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, maxOSVResponseBytes)

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(limited)
		return nil, fmt.Errorf("OSV API returned %d: %s", resp.StatusCode, string(b))
	}

	var result osvBatchResponse
	if err := json.NewDecoder(limited).Decode(&result); err != nil {
		return nil, fmt.Errorf("OSV API response decode error: %w", err)
	}

	// The batch response carries identifiers only; fetch the full record for
	// each advisory before building findings out of them.
	var ids []string
	for _, qr := range result.Results {
		for _, v := range qr.Vulns {
			ids = append(ids, v.ID)
		}
	}
	details := c.hydrate(ids)

	var findings []Finding
	for idx, qr := range result.Results {
		if idx >= len(queried) {
			break
		}
		dep := queried[idx]
		for _, vuln := range qr.Vulns {
			if full, ok := details[vuln.ID]; ok {
				vuln = full
			}
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
	fixedVersion := extractFixedVersion(v.Affected, dep.Version)

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
		Direct:         dep.Direct,
		DependencyPath: dep.Path,
	}
}

// extractFixedVersion picks the version to upgrade to for a dependency
// currently on current.
//
// An advisory usually patches several release branches at once — CVE-2022-28346
// lists fixes in 2.2.28, 3.2.13 and 4.0.4 — and they are not in any particular
// order. Returning the first one tells a project on 3.2.12 to "upgrade" to
// 2.2.28, which is a downgrade into an older branch. The right answer is the
// lowest fix that is actually ahead of the installed version, so the advice
// stays on the branch the project is on whenever that branch has a fix.
//
// When no fix compares as newer (an unparseable version string, or an advisory
// that only lists fixes for older branches) the lowest fix is returned rather
// than nothing: a possibly-imperfect upgrade target beats none at all.
func extractFixedVersion(affected []osvAffected, current string) string {
	var fixes []string
	for _, a := range affected {
		for _, r := range a.Ranges {
			for _, ev := range r.Events {
				if ev.Fixed != "" {
					fixes = append(fixes, ev.Fixed)
				}
			}
		}
	}
	if len(fixes) == 0 {
		return ""
	}

	best := ""
	for _, f := range fixes {
		if compareVersions(f, current) <= 0 {
			continue // not an upgrade
		}
		if best == "" || compareVersions(f, best) < 0 {
			best = f
		}
	}
	if best != "" {
		return best
	}

	lowest := fixes[0]
	for _, f := range fixes[1:] {
		if compareVersions(f, lowest) < 0 {
			lowest = f
		}
	}
	return lowest
}

// compareVersions orders two dotted numeric versions, returning -1, 0 or 1.
// It handles the "1.2.3" shape every ecosystem we parse uses, tolerating a
// leading "v" and ignoring any pre-release or build suffix. Segments that are
// not numbers compare lexically, which keeps the ordering total without
// pulling in a full semver implementation for each ecosystem's own rules.
func compareVersions(a, b string) int {
	as := versionSegments(a)
	bs := versionSegments(b)

	for i := 0; i < len(as) || i < len(bs); i++ {
		// A version that simply stops is padded with zeros, so "1.2" and
		// "1.2.0" are the same release.
		x, y := "0", "0"
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}

		xn, xErr := strconv.Atoi(x)
		yn, yErr := strconv.Atoi(y)
		switch {
		case xErr == nil && yErr == nil:
			if xn != yn {
				if xn < yn {
					return -1
				}
				return 1
			}
		case x != y:
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// versionSegments splits a version into its dotted components, dropping a
// leading "v" and any pre-release or build metadata.
func versionSegments(v string) []string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i != -1 {
		v = v[:i]
	}
	if v == "" {
		return nil
	}
	return strings.Split(v, ".")
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
