package reporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/filipi86/drogonsec/internal/analyzer"
)

func TestNewSelectsAReporterPerFormat(t *testing.T) {
	tests := []struct {
		format string
		want   Reporter
	}{
		{"text", &TextReporter{}},
		{"", &TextReporter{}}, // the default
		{"TEXT", &TextReporter{}},
		{"json", &JSONReporter{}},
		{"Json", &JSONReporter{}},
		{"sarif", &SARIFReporter{}},
		{"html", &HTMLReporter{}},
		{"cyclonedx", &CycloneDXReporter{}},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			got, err := New(tt.format)
			if err != nil {
				t.Fatalf("New(%q) returned error: %v", tt.format, err)
			}
			if gotType, wantType := typeName(got), typeName(tt.want); gotType != wantType {
				t.Errorf("New(%q) = %s, want %s", tt.format, gotType, wantType)
			}
		})
	}
}

func TestNewRejectsUnknownFormats(t *testing.T) {
	for _, format := range []string{"xml", "pdf", "spdx", "csv", "  json  "} {
		t.Run(format, func(t *testing.T) {
			r, err := New(format)
			if err == nil {
				t.Fatalf("New(%q) = %T, want an error", format, r)
			}
			// The message has to name the alternatives; it is what the user
			// sees after a typo on --format.
			for _, want := range []string{"text", "json", "sarif", "html", "cyclonedx"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention the %q format", err, want)
				}
			}
		})
	}
}

func typeName(r Reporter) string {
	switch r.(type) {
	case *TextReporter:
		return "TextReporter"
	case *JSONReporter:
		return "JSONReporter"
	case *SARIFReporter:
		return "SARIFReporter"
	case *HTMLReporter:
		return "HTMLReporter"
	case *CycloneDXReporter:
		return "CycloneDXReporter"
	default:
		return "unknown"
	}
}

func TestJSONReporterEmitsEveryEngine(t *testing.T) {
	var buf bytes.Buffer
	if err := (&JSONReporter{}).Write(fullResult(), &buf); err != nil {
		t.Fatalf("JSON Write returned error: %v", err)
	}

	var out struct {
		Version      string `json:"version"`
		Target       string `json:"target"`
		SASTFindings []struct {
			RuleID string `json:"rule_id"`
		} `json:"sast_findings"`
		SCAFindings []struct {
			CVE string `json:"cve"`
		} `json:"sca_findings"`
		LeakFindings []struct {
			RuleID string `json:"rule_id"`
		} `json:"leak_findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("emitted JSON is not valid: %v\n%s", err, buf.String())
	}

	if len(out.SASTFindings) != 1 || out.SASTFindings[0].RuleID != "PY-001" {
		t.Errorf("sast_findings = %+v, want the PY-001 finding", out.SASTFindings)
	}
	if len(out.SCAFindings) != 1 || out.SCAFindings[0].CVE != "CVE-2021-44228" {
		t.Errorf("sca_findings = %+v, want the Log4Shell finding", out.SCAFindings)
	}
	if len(out.LeakFindings) != 1 || out.LeakFindings[0].RuleID != "LEAK-001" {
		t.Errorf("leak_findings = %+v, want the LEAK-001 finding", out.LeakFindings)
	}
	if out.Version != "0.2.0" {
		t.Errorf("version = %q, want the scan's version", out.Version)
	}
}

func TestJSONReporterEmptyScan(t *testing.T) {
	var buf bytes.Buffer
	if err := (&JSONReporter{}).Write(&analyzer.ScanResult{TargetPath: "/repo"}, &buf); err != nil {
		t.Fatalf("JSON Write returned error: %v", err)
	}
	if !json.Valid(buf.Bytes()) {
		t.Errorf("emitted JSON is not valid for an empty scan:\n%s", buf.String())
	}
}

// TestHTMLReporterEscapesScannedContent is the one that matters for the HTML
// output: every string in a report comes from the repository being scanned,
// which is untrusted by definition. An unescaped angle bracket turns the
// report into script that runs when someone opens it.
func TestHTMLReporterEscapesScannedContent(t *testing.T) {
	const payload = `<script>alert('xss')</script>`

	result := fullResult()
	result.SASTFindings[0].Title = "SQL Injection " + payload
	result.SASTFindings[0].Description = payload
	result.SASTFindings[0].File = "/repo/" + payload + ".py"
	result.SASTFindings[0].Remediation = payload
	result.LeakFindings[0].Type = payload
	result.LeakFindings[0].Match = payload
	result.SCAFindings[0].PackageName = payload
	result.SCAFindings[0].Description = payload
	result.SCAFindings[0].Advisory = "javascript:alert('xss')"

	var buf bytes.Buffer
	if err := (&HTMLReporter{}).Write(result, &buf); err != nil {
		t.Fatalf("HTML Write returned error: %v", err)
	}
	html := buf.String()

	if strings.Contains(html, payload) {
		t.Error("the report contains an unescaped <script> tag from scanned content; " +
			"opening it would execute code from the scanned repository")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("the payload does not appear escaped either; the assertion above " +
			"may be passing because the field was dropped rather than escaped")
	}
	// A javascript: advisory URL must not survive into an href.
	if strings.Contains(html, `href="javascript:`) {
		t.Error("a javascript: URL was emitted into an href")
	}
}

func TestHTMLReporterEmitsADocument(t *testing.T) {
	var buf bytes.Buffer
	if err := (&HTMLReporter{}).Write(fullResult(), &buf); err != nil {
		t.Fatalf("HTML Write returned error: %v", err)
	}
	html := buf.String()

	for _, want := range []string{"<html", "</html>", "<body", "</body>"} {
		if !strings.Contains(html, want) {
			t.Errorf("the report has no %s", want)
		}
	}
	// Each engine's section should be present when it has findings.
	for _, want := range []string{"SAST", "Leak", "SCA"} {
		if !strings.Contains(html, want) {
			t.Errorf("the report has no %s section", want)
		}
	}
}

func TestTextReporterWritesEveryEngine(t *testing.T) {
	var buf bytes.Buffer
	if err := (&TextReporter{}).Write(fullResult(), &buf); err != nil {
		t.Fatalf("text Write returned error: %v", err)
	}
	out := buf.String()

	for _, want := range []string{"PY-001", "LEAK-001", "CVE-2021-44228", "log4j-core"} {
		if !strings.Contains(out, want) {
			t.Errorf("the text report does not mention %q", want)
		}
	}
}

// TestTextReporterEmitsNothingForACleanScan documents the split with the CLI:
// the reporter writes finding sections only, and the counts and the "no issues"
// summary are printed by cli.PrintScanSummary. A clean scan therefore produces
// no reporter output at all, which is why --output on a clean scan writes an
// empty file.
func TestTextReporterEmitsNothingForACleanScan(t *testing.T) {
	var buf bytes.Buffer
	if err := (&TextReporter{}).Write(&analyzer.ScanResult{TargetPath: "/repo"}, &buf); err != nil {
		t.Fatalf("text Write returned error on an empty scan: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("the text reporter wrote %d bytes for a clean scan, want none "+
			"(the summary belongs to the CLI):\n%s", buf.Len(), buf.String())
	}
}

// TestSafeURLRejectsNonHTTPSchemes covers the advisory links that end up as
// href attributes in the HTML report.
func TestSafeURLRejectsNonHTTPSchemes(t *testing.T) {
	hostile := []string{
		"javascript:alert(1)",
		"JavaScript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"vbscript:msgbox(1)",
		"file:///etc/passwd",
	}

	for _, raw := range hostile {
		t.Run(raw, func(t *testing.T) {
			got := safeURL(raw)
			lower := strings.ToLower(got)
			if strings.HasPrefix(lower, "javascript:") ||
				strings.HasPrefix(lower, "data:") ||
				strings.HasPrefix(lower, "vbscript:") ||
				strings.HasPrefix(lower, "file:") {
				t.Errorf("safeURL(%q) = %q, which still carries a dangerous scheme", raw, got)
			}
		})
	}
}

func TestSafeURLKeepsRealAdvisoryLinks(t *testing.T) {
	for _, raw := range []string{
		"https://osv.dev/vulnerability/CVE-2021-44228",
		"http://example.com/advisory",
	} {
		if got := safeURL(raw); got != raw {
			t.Errorf("safeURL(%q) = %q, want it unchanged", raw, got)
		}
	}
}
