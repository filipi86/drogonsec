package analyzer

import (
	"time"

	"github.com/drogonsec/drogonsec/internal/config"
)

// Finding represents a single security vulnerability or issue found
type Finding struct {
	ID          string              `json:"id"`
	Type        config.FindingType  `json:"type"`
	Language    config.Language     `json:"language"`
	Severity    config.Severity     `json:"severity"`
	Title       string              `json:"title"`
	Description string              `json:"description"`
	File        string              `json:"file"`
	Line        int                 `json:"line"`
	Column      int                 `json:"column"`
	Code        string              `json:"code"`        // vulnerable code snippet
	RuleID      string              `json:"rule_id"`
	OWASP       config.OWASPCategory `json:"owasp"`
	CWE         string              `json:"cwe"`         // e.g., "CWE-89"
	CVSS        float64             `json:"cvss"`
	References  []string            `json:"references"`
	Remediation string              `json:"remediation"`   // static remediation
	AIRemediation string            `json:"ai_remediation,omitempty"` // Claude AI suggestion
	FalsePositive bool              `json:"false_positive"`
}

// SCAFinding represents a vulnerable dependency found
type SCAFinding struct {
	PackageName    string          `json:"package_name"`
	PackageVersion string          `json:"package_version"`
	FixedVersion   string          `json:"fixed_version,omitempty"`
	Ecosystem      string          `json:"ecosystem"`
	ManifestFile   string          `json:"manifest_file"`
	Severity       config.Severity `json:"severity"`
	CVE            string          `json:"cve"`
	CVSS           float64         `json:"cvss"`
	Description    string          `json:"description"`
	Advisory       string          `json:"advisory_url"`
	OWASP          config.OWASPCategory `json:"owasp"`
}

// LeakFinding represents a detected secret or credential leak
type LeakFinding struct {
	Type          string          `json:"type"`          // "AWS Key", "GitHub Token", etc.
	File          string          `json:"file"`
	Line          int             `json:"line"`
	Match         string          `json:"match"`         // redacted value
	RuleID        string          `json:"rule_id"`
	Severity      config.Severity `json:"severity"`
	Description   string          `json:"description"`
	Entropy       float64         `json:"entropy,omitempty"`
	InGitHistory  bool            `json:"in_git_history,omitempty"`
	CommitHash    string          `json:"commit_hash,omitempty"`
	AIRemediation string          `json:"ai_remediation,omitempty"`
}

// ScanResult holds the complete result of a scan
type ScanResult struct {
	// Metadata
	TargetPath  string        `json:"target_path"`
	ScanTime    time.Time     `json:"scan_time"`
	Duration    time.Duration `json:"duration"`
	Version     string        `json:"version"`

	// Findings
	SASTFindings []Finding    `json:"sast_findings"`
	SCAFindings  []SCAFinding `json:"sca_findings"`
	LeakFindings []LeakFinding `json:"leak_findings"`

	// Statistics
	Stats ScanStats `json:"stats"`

	// Files scanned
	FilesScanned   int      `json:"files_scanned"`
	FilesSkipped   int      `json:"files_skipped"`
	LanguagesFound []string `json:"languages_found"`
}

// ScanStats aggregates statistics about findings
type ScanStats struct {
	TotalFindings    int `json:"total_findings"`
	CriticalCount    int `json:"critical"`
	HighCount        int `json:"high"`
	MediumCount      int `json:"medium"`
	LowCount         int `json:"low"`
	InfoCount        int `json:"info"`

	SASTCount   int `json:"sast_count"`
	SCACount    int `json:"sca_count"`
	LeaksCount  int `json:"leaks_count"`
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
