package analyzer

import (
	"time"

	"github.com/filipi86/drogonsec/internal/config"
)

// Finding represents a single security vulnerability or issue found
type Finding struct {
	ID            string               `json:"id"`
	Type          config.FindingType   `json:"type"`
	Language      config.Language      `json:"language"`
	Severity      config.Severity      `json:"severity"`
	Title         string               `json:"title"`
	Description   string               `json:"description"`
	File          string               `json:"file"`
	Line          int                  `json:"line"`
	Column        int                  `json:"column"`
	Code          string               `json:"code"` // vulnerable code snippet
	RuleID        string               `json:"rule_id"`
	OWASP         config.OWASPCategory `json:"owasp"`
	CWE           string               `json:"cwe"` // e.g., "CWE-89"
	CVSS          float64              `json:"cvss"`
	References    []string             `json:"references"`
	Remediation   string               `json:"remediation"`              // static remediation
	AIRemediation string               `json:"ai_remediation,omitempty"` // AI remediation suggestion
	FalsePositive bool                 `json:"false_positive"`

	// Fingerprint identifies this finding across scans. See Fingerprints.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// SCAFinding represents a vulnerable dependency found
type SCAFinding struct {
	PackageName    string               `json:"package_name"`
	PackageVersion string               `json:"package_version"`
	FixedVersion   string               `json:"fixed_version,omitempty"`
	Ecosystem      string               `json:"ecosystem"`
	ManifestFile   string               `json:"manifest_file"`
	Severity       config.Severity      `json:"severity"`
	CVE            string               `json:"cve"`
	CVSS           float64              `json:"cvss"`
	Description    string               `json:"description"`
	Advisory       string               `json:"advisory_url"`
	OWASP          config.OWASPCategory `json:"owasp"`

	// Direct is false when nothing in the project declares this package: it
	// arrived because another dependency required it. DependencyPath is the
	// chain that introduces it, from a declared dependency inwards and
	// excluding the package itself, so ["express", "cookie"] means express
	// requires cookie which requires this package. Both are empty when the
	// ecosystem's lockfile was absent and only declared dependencies could be
	// read.
	//
	// Converted directly from sca.Finding — keep the fields in step.
	Direct         bool     `json:"direct"`
	DependencyPath []string `json:"dependency_path,omitempty"`

	// Fingerprint identifies this finding across scans. See Fingerprints.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// Dependency represents a single component discovered by the SCA engine.
// It is the inventory used to produce an SBOM, independent of whether the
// component is vulnerable.
type Dependency struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	Manifest  string `json:"manifest"`

	// Direct records whether the project declares this component itself. In an
	// SBOM it is what the root component's own edges are drawn from.
	Direct bool `json:"direct"`

	// Requires is what this component itself depends on, within the same
	// inventory. It carries the dependency graph into the SBOM, where a flat
	// component list cannot say which component pulled in which.
	Requires []DependencyRef `json:"requires,omitempty"`
}

// DependencyRef identifies one component of the inventory.
type DependencyRef struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// LeakFinding represents a detected secret or credential leak
type LeakFinding struct {
	Type          string          `json:"type"` // "AWS Key", "GitHub Token", etc.
	File          string          `json:"file"`
	Line          int             `json:"line"`
	Column        int             `json:"column"`
	Match         string          `json:"match"` // redacted value
	RuleID        string          `json:"rule_id"`
	Severity      config.Severity `json:"severity"`
	Description   string          `json:"description"`
	Entropy       float64         `json:"entropy,omitempty"`
	InGitHistory  bool            `json:"in_git_history,omitempty"`
	CommitHash    string          `json:"commit_hash,omitempty"`
	AIRemediation string          `json:"ai_remediation,omitempty"`

	// Fingerprint identifies this finding across scans. See Fingerprints.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// ScanResult holds the complete result of a scan
type ScanResult struct {
	// Metadata
	TargetPath string        `json:"target_path"`
	ScanTime   time.Time     `json:"scan_time"`
	Duration   time.Duration `json:"duration"`
	Version    string        `json:"version"`

	// Findings
	SASTFindings []Finding     `json:"sast_findings"`
	SCAFindings  []SCAFinding  `json:"sca_findings"`
	LeakFindings []LeakFinding `json:"leak_findings"`

	// Dependencies is the full SCA component inventory (all dependencies,
	// not only vulnerable ones), used to generate an SBOM.
	Dependencies []Dependency `json:"dependencies,omitempty"`

	// Statistics
	Stats ScanStats `json:"stats"`

	// Files scanned
	FilesScanned   int      `json:"files_scanned"`
	FilesSkipped   int      `json:"files_skipped"`
	LanguagesFound []string `json:"languages_found"`
}

// ScanStats aggregates statistics about findings
type ScanStats struct {
	TotalFindings int `json:"total_findings"`
	CriticalCount int `json:"critical"`
	HighCount     int `json:"high"`
	MediumCount   int `json:"medium"`
	LowCount      int `json:"low"`
	InfoCount     int `json:"info"`

	SASTCount  int `json:"sast_count"`
	SCACount   int `json:"sca_count"`
	LeaksCount int `json:"leaks_count"`
}

// HasCritical returns true if any critical findings exist
func (r *ScanResult) HasCritical() bool {
	return r.Stats.CriticalCount > 0
}

// HasHigh returns true if any high severity findings exist
func (r *ScanResult) HasHigh() bool {
	return r.Stats.HighCount > 0
}

// ComputeStats recalculates statistics from findings
func (r *ScanResult) ComputeStats() {
	r.Stats = ScanStats{}

	for _, f := range r.SASTFindings {
		r.Stats.SASTCount++
		r.Stats.TotalFindings++
		r.incrementSeverity(f.Severity)
	}

	for _, f := range r.SCAFindings {
		r.Stats.SCACount++
		r.Stats.TotalFindings++
		r.incrementSeverity(f.Severity)
	}

	for _, f := range r.LeakFindings {
		r.Stats.LeaksCount++
		r.Stats.TotalFindings++
		r.incrementSeverity(f.Severity)
	}
}

func (r *ScanResult) incrementSeverity(s config.Severity) {
	switch s {
	case config.SeverityCritical:
		r.Stats.CriticalCount++
	case config.SeverityHigh:
		r.Stats.HighCount++
	case config.SeverityMedium:
		r.Stats.MediumCount++
	case config.SeverityLow:
		r.Stats.LowCount++
	default:
		r.Stats.InfoCount++
	}
}

// AddSASTFinding appends a SAST finding
func (r *ScanResult) AddSASTFinding(f Finding) {
	r.SASTFindings = append(r.SASTFindings, f)
}

// AddSCAFinding appends a SCA finding
func (r *ScanResult) AddSCAFinding(f SCAFinding) {
	r.SCAFindings = append(r.SCAFindings, f)
}

// AddLeakFinding appends a leak finding
func (r *ScanResult) AddLeakFinding(f LeakFinding) {
	r.LeakFindings = append(r.LeakFindings, f)
}
