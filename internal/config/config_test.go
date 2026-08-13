package config

import (
	"strings"
	"testing"
)

func TestSeverityWeightOrdering(t *testing.T) {
	// The ordering is what --severity filtering and report sorting rely on;
	// the absolute numbers matter less than the relation between them.
	ordered := []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for i := 1; i < len(ordered); i++ {
		lower, higher := ordered[i-1], ordered[i]
		if lower.Weight() >= higher.Weight() {
			t.Errorf("Weight(%s) = %d is not below Weight(%s) = %d",
				lower, lower.Weight(), higher, higher.Weight())
		}
	}
}

func TestSeverityWeightUnknownIsLowest(t *testing.T) {
	// An unrecognised severity must never outrank a real one, so that a typo
	// in a custom rule cannot promote a finding past a --severity filter.
	if got := Severity("NOT-A-SEVERITY").Weight(); got != 0 {
		t.Errorf("Weight of an unknown severity = %d, want 0", got)
	}
	if got := Severity("").Weight(); got != 0 {
		t.Errorf("Weight of an empty severity = %d, want 0", got)
	}
}

// TestFileExtensionMapKeysAreNormalized guards the lookup contract: the
// analyzer looks extensions up after lowercasing them and keeps the leading
// dot, so a key shaped any other way is dead weight that silently never
// matches a file.
func TestFileExtensionMapKeysAreNormalized(t *testing.T) {
	for ext, lang := range FileExtensionMap {
		if !strings.HasPrefix(ext, ".") {
			t.Errorf("extension %q does not start with a dot, so it can never match", ext)
		}
		if ext != strings.ToLower(ext) {
			t.Errorf("extension %q is not lowercase, so the lowercased lookup misses it", ext)
		}
		if lang == "" {
			t.Errorf("extension %q maps to an empty language", ext)
		}
		if lang == LangUnknown {
			t.Errorf("extension %q maps to LangUnknown; drop the entry instead", ext)
		}
	}
}

// TestDefaultIgnorePathsAreMatchable pins the shape the walkers expect. Both
// the SAST file collector and the SCA manifest walker test membership with
// strings.Contains(path, "/"+name+"/"), so a stored entry that has its own
// leading or trailing slash produces a doubled separator and matches nothing.
func TestDefaultIgnorePathsAreMatchable(t *testing.T) {
	seen := make(map[string]bool, len(DefaultIgnorePaths))

	for _, p := range DefaultIgnorePaths {
		if p == "" {
			t.Error("DefaultIgnorePaths contains an empty entry, which would match every path")
			continue
		}
		if strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") {
			t.Errorf("ignore path %q has a leading or trailing slash; the walker adds its own", p)
		}
		if strings.TrimSpace(p) != p {
			t.Errorf("ignore path %q has surrounding whitespace", p)
		}
		if seen[p] {
			t.Errorf("ignore path %q is listed twice", p)
		}
		seen[p] = true
	}
}

// TestDefaultIgnorePathsCoverTheKnownDoubleReportSources keeps the entries that
// exist for a specific reason from being dropped by a future tidy-up: vendored
// code, and the worktree directory that would otherwise make the scanner report
// every finding twice against its own repository.
func TestDefaultIgnorePathsCoverTheKnownDoubleReportSources(t *testing.T) {
	required := []string{".git", "node_modules", "vendor", ".claude", "testdata"}

	for _, want := range required {
		found := false
		for _, p := range DefaultIgnorePaths {
			if p == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DefaultIgnorePaths no longer contains %q", want)
		}
	}
}

func TestOWASPCategoriesAreDistinctAndLabelled(t *testing.T) {
	categories := []OWASPCategory{
		OWASP_A01_BrokenAccessControl,
		OWASP_A02_SecurityMisconfiguration,
		OWASP_A03_SoftwareSupplyChainFailures,
		OWASP_A04_CryptographicFailures,
		OWASP_A05_Injection,
		OWASP_A06_InsecureDesign,
		OWASP_A07_AuthenticationFailures,
		OWASP_A08_SoftwareDataIntegrityFailures,
		OWASP_A09_SecurityLoggingAlertingFailures,
		OWASP_A10_MishandlingExceptionalConditions,
	}

	seen := make(map[OWASPCategory]bool, len(categories))
	for i, c := range categories {
		if seen[c] {
			t.Errorf("OWASP category %q is duplicated", c)
		}
		seen[c] = true

		// SARIF consumers and the HTML report key off this prefix.
		wantPrefix := [...]string{
			"A01:2025", "A02:2025", "A03:2025", "A04:2025", "A05:2025",
			"A06:2025", "A07:2025", "A08:2025", "A09:2025", "A10:2025",
		}[i]
		if !strings.HasPrefix(string(c), wantPrefix) {
			t.Errorf("category %q does not start with %q", c, wantPrefix)
		}
	}
}
