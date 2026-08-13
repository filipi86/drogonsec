package analyzer

import (
	"testing"

	"github.com/filipi86/drogonsec/internal/config"
)

// severities returns the severity of each finding, in order, so a test can
// assert the sequence a reader would see.
func sastSeverities(f []Finding) []config.Severity {
	out := make([]config.Severity, len(f))
	for i, x := range f {
		out[i] = x.Severity
	}
	return out
}

func leakSeverities(f []LeakFinding) []config.Severity {
	out := make([]config.Severity, len(f))
	for i, x := range f {
		out[i] = x.Severity
	}
	return out
}

func scaSeverities(f []SCAFinding) []config.Severity {
	out := make([]config.Severity, len(f))
	for i, x := range f {
		out[i] = x.Severity
	}
	return out
}

func equalSeverities(got, want []config.Severity) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// descending is the order every finding list must end up in.
var descending = []config.Severity{
	config.SeverityCritical,
	config.SeverityHigh,
	config.SeverityMedium,
	config.SeverityLow,
	config.SeverityInfo,
}

// TestSortFindingsOrdersEveryEngineBySeverity is the behaviour a reader depends
// on: the top of every report is the most critical thing found.
func TestSortFindingsOrdersEveryEngineBySeverity(t *testing.T) {
	// Deliberately built in the least helpful order.
	result := &ScanResult{
		SASTFindings: []Finding{
			{RuleID: "a", Severity: config.SeverityLow},
			{RuleID: "b", Severity: config.SeverityCritical},
			{RuleID: "c", Severity: config.SeverityInfo},
			{RuleID: "d", Severity: config.SeverityHigh},
			{RuleID: "e", Severity: config.SeverityMedium},
		},
		LeakFindings: []LeakFinding{
			{RuleID: "a", Severity: config.SeverityInfo},
			{RuleID: "b", Severity: config.SeverityMedium},
			{RuleID: "c", Severity: config.SeverityCritical},
			{RuleID: "d", Severity: config.SeverityLow},
			{RuleID: "e", Severity: config.SeverityHigh},
		},
		SCAFindings: []SCAFinding{
			{CVE: "a", Severity: config.SeverityMedium},
			{CVE: "b", Severity: config.SeverityLow},
			{CVE: "c", Severity: config.SeverityHigh},
			{CVE: "d", Severity: config.SeverityInfo},
			{CVE: "e", Severity: config.SeverityCritical},
		},
	}

	SortFindings(result)

	if got := sastSeverities(result.SASTFindings); !equalSeverities(got, descending) {
		t.Errorf("SAST severities = %v, want %v", got, descending)
	}
	if got := leakSeverities(result.LeakFindings); !equalSeverities(got, descending) {
		t.Errorf("leak severities = %v, want %v", got, descending)
	}
	if got := scaSeverities(result.SCAFindings); !equalSeverities(got, descending) {
		t.Errorf("SCA severities = %v, want %v", got, descending)
	}
}

// TestSortFindingsRanksByCVSSWithinASeverity keeps the worst of a band on top:
// two HIGH findings are not equally urgent if one scores 8.9 and the other 7.0.
func TestSortFindingsRanksByCVSSWithinASeverity(t *testing.T) {
	result := &ScanResult{
		SASTFindings: []Finding{
			{RuleID: "low-score", Severity: config.SeverityHigh, CVSS: 7.1},
			{RuleID: "high-score", Severity: config.SeverityHigh, CVSS: 8.9},
			{RuleID: "mid-score", Severity: config.SeverityHigh, CVSS: 8.0},
		},
		SCAFindings: []SCAFinding{
			{CVE: "CVE-low", Severity: config.SeverityCritical, CVSS: 9.1},
			{CVE: "CVE-high", Severity: config.SeverityCritical, CVSS: 10.0},
		},
	}

	SortFindings(result)

	wantSAST := []string{"high-score", "mid-score", "low-score"}
	for i, want := range wantSAST {
		if got := result.SASTFindings[i].RuleID; got != want {
			t.Errorf("SAST position %d = %q, want %q", i, got, want)
		}
	}
	if got := result.SCAFindings[0].CVE; got != "CVE-high" {
		t.Errorf("SCA first = %q, want the 10.0 finding", got)
	}
}

// TestSortFindingsIsDeterministic matters for anyone diffing two scans: equal
// findings must not shuffle between runs, or every report looks changed.
func TestSortFindingsIsDeterministic(t *testing.T) {
	build := func() *ScanResult {
		return &ScanResult{
			SASTFindings: []Finding{
				{RuleID: "R2", Severity: config.SeverityHigh, CVSS: 8.0, File: "b.go", Line: 10},
				{RuleID: "R1", Severity: config.SeverityHigh, CVSS: 8.0, File: "a.go", Line: 20},
				{RuleID: "R3", Severity: config.SeverityHigh, CVSS: 8.0, File: "a.go", Line: 5},
			},
			LeakFindings: []LeakFinding{
				{RuleID: "L2", Severity: config.SeverityCritical, File: "b.yml", Line: 1},
				{RuleID: "L1", Severity: config.SeverityCritical, File: "a.yml", Line: 9},
			},
		}
	}

	first := build()
	SortFindings(first)
	second := build()
	SortFindings(second)

	for i := range first.SASTFindings {
		if first.SASTFindings[i].RuleID != second.SASTFindings[i].RuleID {
			t.Fatalf("SAST order differs between runs at %d: %q vs %q",
				i, first.SASTFindings[i].RuleID, second.SASTFindings[i].RuleID)
		}
	}

	// Same severity and score: location decides, file before line.
	wantSAST := []string{"R3", "R1", "R2"} // a.go:5, a.go:20, b.go:10
	for i, want := range wantSAST {
		if got := first.SASTFindings[i].RuleID; got != want {
			t.Errorf("SAST position %d = %q, want %q", i, got, want)
		}
	}
	wantLeaks := []string{"L1", "L2"} // a.yml before b.yml
	for i, want := range wantLeaks {
		if got := first.LeakFindings[i].RuleID; got != want {
			t.Errorf("leak position %d = %q, want %q", i, got, want)
		}
	}
}

func TestSortFindingsHandlesEmptyAndNil(t *testing.T) {
	SortFindings(nil) // must not panic

	empty := &ScanResult{}
	SortFindings(empty)
	if len(empty.SASTFindings) != 0 || len(empty.LeakFindings) != 0 || len(empty.SCAFindings) != 0 {
		t.Error("sorting an empty result invented findings")
	}
}

// TestSortFindingsKeepsUnknownSeveritiesLast guards the ordering against a
// typo in a custom rule: an unrecognised severity weighs zero, so it sinks to
// the bottom instead of displacing a real CRITICAL.
func TestSortFindingsKeepsUnknownSeveritiesLast(t *testing.T) {
	result := &ScanResult{
		SASTFindings: []Finding{
			{RuleID: "typo", Severity: config.Severity("CRITCAL")},
			{RuleID: "real", Severity: config.SeverityCritical},
			{RuleID: "info", Severity: config.SeverityInfo},
		},
	}

	SortFindings(result)

	if got := result.SASTFindings[0].RuleID; got != "real" {
		t.Errorf("first finding = %q, want the genuine CRITICAL", got)
	}
	if got := result.SASTFindings[len(result.SASTFindings)-1].RuleID; got != "typo" {
		t.Errorf("last finding = %q, want the unrecognised severity", got)
	}
}
