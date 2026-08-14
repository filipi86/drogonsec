package reporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/filipi86/drogonsec/internal/analyzer"
	"github.com/filipi86/drogonsec/internal/config"
)

// sarifDoc is a reading view of the emitted document. The writer's own structs
// are not reused, so a change to them cannot silently change what this test
// believes the output is.
type sarifDoc struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name           string `json:"name"`
				Version        string `json:"version"`
				InformationURI string `json:"informationUri"`
				Rules          []struct {
					ID               string `json:"id"`
					Name             string `json:"name"`
					ShortDescription struct {
						Text string `json:"text"`
					} `json:"shortDescription"`
					Properties map[string]interface{} `json:"properties"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine   int `json:"startLine"`
						StartColumn int `json:"startColumn"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func writeSARIF(t *testing.T, result *analyzer.ScanResult) sarifDoc {
	t.Helper()
	var buf bytes.Buffer
	if err := (&SARIFReporter{}).Write(result, &buf); err != nil {
		t.Fatalf("SARIF Write returned error: %v", err)
	}

	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("emitted SARIF is not valid JSON: %v\n%s", err, buf.String())
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("got %d runs, want exactly 1", len(doc.Runs))
	}
	return doc
}

// fullResult is a scan result carrying one finding of each kind.
func fullResult() *analyzer.ScanResult {
	return &analyzer.ScanResult{
		TargetPath: "/repo",
		Version:    "0.2.0",
		SASTFindings: []analyzer.Finding{{
			RuleID:      "PY-001",
			Title:       "SQL Injection",
			Description: "User input concatenated into a query",
			Severity:    config.SeverityCritical,
			File:        "/repo/api/db.py",
			Line:        42,
			Column:      7,
			CWE:         "CWE-89",
			CVSS:        9.8,
			OWASP:       config.OWASP_A05_Injection,
			Remediation: "Use parameterised queries",
		}},
		LeakFindings: []analyzer.LeakFinding{{
			RuleID:      "LEAK-001",
			Type:        "AWS Access Key ID",
			Description: "AWS access key committed",
			Severity:    config.SeverityCritical,
			File:        "/repo/config/prod.yml",
			Line:        3,
			Column:      12,
			Match:       "AKI*****************",
		}},
		SCAFindings: []analyzer.SCAFinding{{
			PackageName:    "log4j-core",
			PackageVersion: "2.14.1",
			FixedVersion:   "2.17.1",
			Ecosystem:      "maven",
			ManifestFile:   "/repo/pom.xml",
			Severity:       config.SeverityCritical,
			CVE:            "CVE-2021-44228",
			CVSS:           10.0,
			Description:    "Log4Shell: remote code execution via JNDI lookup",
			Advisory:       "https://osv.dev/vulnerability/CVE-2021-44228",
			OWASP:          config.OWASP_A03_SoftwareSupplyChainFailures,
		}},
	}
}

// TestSARIFIncludesEveryEngine is the point of the format: SARIF is what
// reaches GitHub Code Scanning, and a whole engine missing from it means those
// vulnerabilities are invisible in the Security tab even though the scan found
// them and every other reporter shows them.
func TestSARIFIncludesEveryEngine(t *testing.T) {
	doc := writeSARIF(t, fullResult())
	run := doc.Runs[0]

	byRule := make(map[string]bool, len(run.Results))
	for _, r := range run.Results {
		byRule[r.RuleID] = true
	}

	for _, want := range []struct{ engine, ruleID string }{
		{"SAST", "PY-001"},
		{"leaks", "LEAK-001"},
		{"SCA", "CVE-2021-44228"},
	} {
		if !byRule[want.ruleID] {
			t.Errorf("no %s result in the SARIF output (expected rule %q); "+
				"those findings never reach GitHub Code Scanning", want.engine, want.ruleID)
		}
	}

	if len(run.Results) != 3 {
		t.Errorf("got %d results, want 3 (one per engine)", len(run.Results))
	}
}

// TestSARIFDeclaresEveryReferencedRule enforces the SARIF requirement that
// each result's ruleId resolves to a rule in the driver: consumers reject a
// document with a dangling reference.
func TestSARIFDeclaresEveryReferencedRule(t *testing.T) {
	doc := writeSARIF(t, fullResult())
	run := doc.Runs[0]

	declared := make(map[string]bool, len(run.Tool.Driver.Rules))
	for _, r := range run.Tool.Driver.Rules {
		if r.ID == "" {
			t.Error("a rule was declared with an empty id")
		}
		if declared[r.ID] {
			t.Errorf("rule %q is declared more than once", r.ID)
		}
		declared[r.ID] = true
	}

	for _, res := range run.Results {
		if !declared[res.RuleID] {
			t.Errorf("result references rule %q, which the driver does not declare", res.RuleID)
		}
	}
}

func TestSARIFEnvelope(t *testing.T) {
	doc := writeSARIF(t, fullResult())

	if doc.Version != "2.1.0" {
		t.Errorf("version = %q, want %q", doc.Version, "2.1.0")
	}
	if !strings.Contains(doc.Schema, "sarif") {
		t.Errorf("$schema = %q, want it to reference the SARIF schema", doc.Schema)
	}
	driver := doc.Runs[0].Tool.Driver
	if driver.Name == "" {
		t.Error("the driver has no name; GitHub keys the Code Scanning tool on it")
	}
	if driver.Version != "0.2.0" {
		t.Errorf("driver version = %q, want the scan's version", driver.Version)
	}
	if driver.InformationURI == "" {
		t.Error("the driver has no informationUri")
	}
}

// TestSARIFPathsAreRelativeToTheScanTarget matters twice over: absolute paths
// leak the layout of the machine that ran the scan, and GitHub cannot map a
// finding onto a file in the repository unless the path is repository-relative.
func TestSARIFPathsAreRelativeToTheScanTarget(t *testing.T) {
	doc := writeSARIF(t, fullResult())

	for _, res := range doc.Runs[0].Results {
		for _, loc := range res.Locations {
			uri := loc.PhysicalLocation.ArtifactLocation.URI
			if uri == "" {
				t.Errorf("result %q has an empty artifact URI", res.RuleID)
				continue
			}
			if strings.HasPrefix(uri, "/") {
				t.Errorf("result %q has absolute path %q; it exposes the scanning "+
					"host's layout and GitHub cannot map it to a file", res.RuleID, uri)
			}
			if strings.Contains(uri, `\`) {
				t.Errorf("URI %q uses backslashes; SARIF requires forward slashes", uri)
			}
		}
	}
}

// TestSARIFRegionsAreValid guards the constraint that made GitHub reject
// earlier documents: startLine must be at least 1.
func TestSARIFRegionsAreValid(t *testing.T) {
	result := fullResult()
	// A finding with no position information, as produced by a file-scoped rule.
	result.SASTFindings[0].Line = 0
	result.SASTFindings[0].Column = 0

	doc := writeSARIF(t, result)

	for _, res := range doc.Runs[0].Results {
		for _, loc := range res.Locations {
			region := loc.PhysicalLocation.Region
			if region.StartLine < 1 {
				t.Errorf("result %q has startLine %d; SARIF requires >= 1 and "+
					"consumers reject the document", res.RuleID, region.StartLine)
			}
			// startColumn is omitted rather than fabricated when unknown, so
			// zero here means the field was absent, which is valid.
			if region.StartColumn < 0 {
				t.Errorf("result %q has a negative startColumn %d", res.RuleID, region.StartColumn)
			}
		}
	}
}

// TestSARIFLeaksCarryTheirColumn keeps secrets anchored where they actually
// are. Without startColumn the region runs from the start of the line, so an
// editor underlines the whole line and points a reviewer at the variable name
// instead of the credential.
func TestSARIFLeaksCarryTheirColumn(t *testing.T) {
	doc := writeSARIF(t, fullResult())

	for _, res := range doc.Runs[0].Results {
		if res.RuleID != "LEAK-001" {
			continue
		}
		if got := res.Locations[0].PhysicalLocation.Region.StartColumn; got != 12 {
			t.Errorf("leak result has startColumn %d, want 12", got)
		}
		return
	}
	t.Error("no LEAK-001 result in the emitted document")
}

func TestSARIFLevelMapping(t *testing.T) {
	tests := []struct {
		severity config.Severity
		want     string
	}{
		{config.SeverityCritical, "error"},
		{config.SeverityHigh, "error"},
		{config.SeverityMedium, "warning"},
		{config.SeverityLow, "note"},
		{config.SeverityInfo, "note"},
		{config.Severity("UNRECOGNISED"), "note"},
	}

	for _, tt := range tests {
		if got := sarifLevel(tt.severity); got != tt.want {
			t.Errorf("sarifLevel(%s) = %q, want %q", tt.severity, got, tt.want)
		}
	}
}

func TestSARIFEmptyScanIsStillValid(t *testing.T) {
	doc := writeSARIF(t, &analyzer.ScanResult{TargetPath: "/repo", Version: "0.2.0"})

	if len(doc.Runs[0].Results) != 0 {
		t.Errorf("got %d results for an empty scan, want 0", len(doc.Runs[0].Results))
	}
	if doc.Version != "2.1.0" {
		t.Errorf("version = %q, want %q even with no findings", doc.Version, "2.1.0")
	}
}

func TestSarifRelPath(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		file       string
		want       string
		wantAbsOut bool
	}{
		{name: "nested file", target: "/repo", file: "/repo/api/db.py", want: "api/db.py"},
		{name: "file at the root", target: "/repo", file: "/repo/main.go", want: "main.go"},
		{name: "target with a trailing slash", target: "/repo/", file: "/repo/main.go", want: "main.go"},
		{name: "same path", target: "/repo", file: "/repo", want: "."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sarifRelPath(tt.target, tt.file); got != tt.want {
				t.Errorf("sarifRelPath(%q, %q) = %q, want %q", tt.target, tt.file, got, tt.want)
			}
		})
	}
}
