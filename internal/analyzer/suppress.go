package analyzer

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/filipi86/drogonsec/internal/config"
)

// suppressor applies the user-configured false-positive suppressions loaded
// from the `suppressions:` section of .drogonsec.yaml. A finding is dropped
// only when BOTH its rule ID matches an entry's rule_id AND its file matches
// that entry's file pattern. Suppressions are always rule- and file-scoped —
// there is deliberately no "suppress every rule in this file" form, so a real
// vulnerability of a different class in a suppressed file still surfaces.
type suppressor struct {
	rules  []config.Suppression
	target string
}

func newSuppressor(cfg *config.ScanConfig) *suppressor {
	return &suppressor{rules: cfg.Suppressions, target: cfg.TargetPath}
}

// matches reports whether a finding for ruleID at absPath is suppressed.
// The file pattern is matched against the path relative to the scan target
// (so entries stay stable regardless of where the repo is checked out) as:
//   - an exact relative-path or path-suffix match, or
//   - a path.Match glob against the full relative path, or
//   - a path.Match glob against the base name when the pattern has no slash
//     (e.g. "*_test.go").
func (s *suppressor) matches(ruleID, absPath string) bool {
	if len(s.rules) == 0 || ruleID == "" {
		return false
	}

	rel := absPath
	if r, err := filepath.Rel(s.target, absPath); err == nil {
		rel = r
	}
	rel = filepath.ToSlash(rel)
	base := path.Base(rel)

	for _, sup := range s.rules {
		if sup.RuleID != ruleID {
			continue
		}
		pat := filepath.ToSlash(sup.File)
		if rel == pat || strings.HasSuffix(rel, "/"+pat) {
			return true
		}
		if ok, err := path.Match(pat, rel); err == nil && ok {
			return true
		}
		if !strings.Contains(pat, "/") {
			if ok, err := path.Match(pat, base); err == nil && ok {
				return true
			}
		}
	}
	return false
}

// applySuppressions removes findings that match a configured suppression.
// It runs after all engines complete and before statistics are computed, and
// reports how many findings were dropped so the suppression is never silent.
func (a *Analyzer) applySuppressions(result *ScanResult) {
	sup := newSuppressor(a.cfg)
	if len(sup.rules) == 0 {
		return
	}

	suppressed := 0

	keptSAST := result.SASTFindings[:0]
	for _, f := range result.SASTFindings {
		if sup.matches(f.RuleID, f.File) {
			suppressed++
			continue
		}
		keptSAST = append(keptSAST, f)
	}
	result.SASTFindings = keptSAST

	keptLeaks := result.LeakFindings[:0]
	for _, f := range result.LeakFindings {
		if sup.matches(f.RuleID, f.File) {
			suppressed++
			continue
		}
		keptLeaks = append(keptLeaks, f)
	}
	result.LeakFindings = keptLeaks

	// SCA findings have no rule ID; their CVE plays that role and the
	// manifest file plays the file role.
	keptSCA := result.SCAFindings[:0]
	for _, f := range result.SCAFindings {
		if sup.matches(f.CVE, f.ManifestFile) {
			suppressed++
			continue
		}
		keptSCA = append(keptSCA, f)
	}
	result.SCAFindings = keptSCA

	if suppressed > 0 {
		fmt.Printf("\n  %s %d finding(s) suppressed via .drogonsec.yaml (documented false positives)\n",
			color.YellowString("⚠"), suppressed)
	}
}
