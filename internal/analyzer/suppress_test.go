package analyzer

import (
	"path/filepath"
	"testing"

	"github.com/filipi86/drogonsec/internal/config"
)

func TestSuppressorMatches(t *testing.T) {
	target := filepath.FromSlash("/repo")
	sup := &suppressor{
		target: target,
		rules: []config.Suppression{
			{RuleID: "LEAK-080", File: "internal/leaks/detector.go", Reason: "self-match"},
			{RuleID: "GO-005", File: "internal/engine/engine_test.go", Reason: "fixture"},
			{RuleID: "LEAK-001", File: "*_test.go", Reason: "any test file"},
			{RuleID: "GO-2026-5932", File: "go.mod", Reason: "unreachable"},
		},
	}

	abs := func(rel string) string { return filepath.Join(target, filepath.FromSlash(rel)) }

	cases := []struct {
		name   string
		ruleID string
		path   string
		want   bool
	}{
		{"exact rule and file", "LEAK-080", abs("internal/leaks/detector.go"), true},
		{"right file wrong rule", "LEAK-081", abs("internal/leaks/detector.go"), false},
		{"right rule wrong file", "LEAK-080", abs("internal/leaks/other.go"), false},
		{"basename glob matches test file", "LEAK-001", abs("internal/leaks/detector_test.go"), true},
		{"basename glob ignores non-test", "LEAK-001", abs("internal/leaks/detector.go"), false},
		{"manifest at repo root", "GO-2026-5932", abs("go.mod"), true},
		{"empty rule id never matches", "", abs("go.mod"), false},
		{"unlisted rule never matches", "SQL-001", abs("main.go"), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sup.matches(tc.ruleID, tc.path); got != tc.want {
				t.Errorf("matches(%q, %q) = %v, want %v", tc.ruleID, tc.path, got, tc.want)
			}
		})
	}
}

func TestSuppressorEmptyRulesNeverMatch(t *testing.T) {
	sup := &suppressor{target: filepath.FromSlash("/repo")}
	if sup.matches("LEAK-080", filepath.FromSlash("/repo/x.go")) {
		t.Error("suppressor with no rules should never match")
	}
}

func TestApplySuppressions(t *testing.T) {
	target := filepath.FromSlash("/repo")
	a := &Analyzer{cfg: &config.ScanConfig{
		TargetPath: target,
		Suppressions: []config.Suppression{
			{RuleID: "LEAK-080", File: "internal/leaks/detector.go", Reason: "self-match"},
			{RuleID: "GO-2026-5932", File: "go.mod", Reason: "unreachable"},
		},
	}}

	result := &ScanResult{
		SASTFindings: []Finding{
			{RuleID: "GO-001", File: filepath.Join(target, "main.go")},
		},
		LeakFindings: []LeakFinding{
			{RuleID: "LEAK-080", File: filepath.Join(target, filepath.FromSlash("internal/leaks/detector.go"))}, // suppressed
			{RuleID: "LEAK-080", File: filepath.Join(target, filepath.FromSlash("internal/leaks/real.go"))},     // kept
		},
		SCAFindings: []SCAFinding{
			{CVE: "GO-2026-5932", ManifestFile: filepath.Join(target, "go.mod")}, // suppressed
			{CVE: "GO-2026-1111", ManifestFile: filepath.Join(target, "go.mod")}, // kept
		},
	}

	a.applySuppressions(result)

	if len(result.SASTFindings) != 1 {
		t.Errorf("SAST: got %d findings, want 1", len(result.SASTFindings))
	}
	if len(result.LeakFindings) != 1 {
		t.Errorf("Leaks: got %d findings, want 1 (one suppressed)", len(result.LeakFindings))
	}
	if len(result.LeakFindings) == 1 && result.LeakFindings[0].File == filepath.Join(target, filepath.FromSlash("internal/leaks/detector.go")) {
		t.Error("Leaks: suppressed the wrong finding")
	}
	if len(result.SCAFindings) != 1 {
		t.Errorf("SCA: got %d findings, want 1 (one suppressed)", len(result.SCAFindings))
	}
	if len(result.SCAFindings) == 1 && result.SCAFindings[0].CVE != "GO-2026-1111" {
		t.Errorf("SCA: kept the wrong finding: %s", result.SCAFindings[0].CVE)
	}
}
