package analyzer

import (
	"strings"
	"testing"

	"github.com/filipi86/drogonsec/internal/config"
)

// scanWith builds a result and fingerprints it, so a test can state the inputs
// and read back the identities they produce.
func scanWith(target string, sast []Finding, leaks []LeakFinding, sca []SCAFinding) *ScanResult {
	result := &ScanResult{TargetPath: target, SASTFindings: sast, LeakFindings: leaks, SCAFindings: sca}
	Fingerprints(result)
	return result
}

// TestFingerprintSurvivesAnEditAbove is the property the whole scheme exists
// for. The old SAST identifier was rule-basename-line, so adding an import at
// the top of a file changed the identity of every finding below it: an editor
// would call them all new, and code scanning would close every alert and open a
// fresh copy.
func TestFingerprintSurvivesAnEditAbove(t *testing.T) {
	before := scanWith("/repo", []Finding{
		{RuleID: "PY-001", File: "/repo/app/users.py", Line: 42, Code: "cursor.execute(sql % uid)"},
	}, nil, nil)

	after := scanWith("/repo", []Finding{
		// Same finding, ten lines further down after an import block was added.
		{RuleID: "PY-001", File: "/repo/app/users.py", Line: 52, Code: "cursor.execute(sql % uid)"},
	}, nil, nil)

	if before.SASTFindings[0].Fingerprint != after.SASTFindings[0].Fingerprint {
		t.Errorf("the finding moved and changed identity: %q then %q",
			before.SASTFindings[0].Fingerprint, after.SASTFindings[0].Fingerprint)
	}
}

func TestFingerprintIgnoresReindentation(t *testing.T) {
	// Wrapping a statement in an if, or running a formatter, changes the
	// leading whitespace and nothing about the flaw.
	plain := scanWith("/repo", []Finding{
		{RuleID: "PY-001", File: "/repo/a.py", Code: "cursor.execute(sql % uid)"},
	}, nil, nil)
	indented := scanWith("/repo", []Finding{
		{RuleID: "PY-001", File: "/repo/a.py", Code: "\t    cursor.execute(sql  %  uid)  "},
	}, nil, nil)

	if plain.SASTFindings[0].Fingerprint != indented.SASTFindings[0].Fingerprint {
		t.Error("re-indenting the line changed the finding's identity")
	}
}

func TestFingerprintIsIndependentOfTheCheckoutDirectory(t *testing.T) {
	// The same repository scanned on a developer's machine and in CI has to
	// produce the same identities, or every alert reopens on the first CI run.
	//
	// The sample code is deliberately inert. What it says does not matter to a
	// fingerprint, and writing a real vulnerable pattern here would make the
	// scanner flag its own test data when it scans this repository.
	const sample = "cfg.Verify = caller.Choice()"
	local := scanWith("/home/alice/work/repo", []Finding{
		{RuleID: "GO-005", File: "/home/alice/work/repo/pkg/tls.go", Code: sample},
	}, nil, nil)
	ci := scanWith("/github/workspace", []Finding{
		{RuleID: "GO-005", File: "/github/workspace/pkg/tls.go", Code: sample},
	}, nil, nil)

	if local.SASTFindings[0].Fingerprint != ci.SASTFindings[0].Fingerprint {
		t.Error("the fingerprint carries the checkout path")
	}
}

func TestFingerprintDistinguishesGenuinelyDifferentFindings(t *testing.T) {
	result := scanWith("/repo", []Finding{
		{RuleID: "PY-001", File: "/repo/a.py", Code: "cursor.execute(sql % uid)"},
		// Same rule and code, different file: two things to fix.
		{RuleID: "PY-001", File: "/repo/b.py", Code: "cursor.execute(sql % uid)"},
		// Same rule and file, different code: also two things to fix.
		{RuleID: "PY-001", File: "/repo/a.py", Code: "cursor.execute(sql % name)"},
		// Different rule on identical code.
		{RuleID: "PY-009", File: "/repo/a.py", Code: "cursor.execute(sql % uid)"},
	}, nil, nil)

	seen := make(map[string]int)
	for _, f := range result.SASTFindings {
		seen[f.Fingerprint]++
	}
	if len(seen) != 4 {
		t.Errorf("4 distinct findings produced %d identities: %v", len(seen), seen)
	}
}

// TestFingerprintNumbersIndistinguishableFindings covers the case the inputs
// cannot separate: one rule matching identical text twice in one file. They are
// two findings and need two identities, so an occurrence number is appended.
func TestFingerprintNumbersIndistinguishableFindings(t *testing.T) {
	result := scanWith("/repo", []Finding{
		{RuleID: "JS-004", File: "/repo/a.js", Line: 10, Code: `const key = "AKIA..."`},
		{RuleID: "JS-004", File: "/repo/a.js", Line: 80, Code: `const key = "AKIA..."`},
		{RuleID: "JS-004", File: "/repo/a.js", Line: 90, Code: `const key = "AKIA..."`},
	}, nil, nil)

	first := result.SASTFindings[0].Fingerprint
	want := []string{first, first + "-2", first + "-3"}
	for i, f := range result.SASTFindings {
		if f.Fingerprint != want[i] {
			t.Errorf("finding %d = %q, want %q", i, f.Fingerprint, want[i])
		}
	}
}

func TestFingerprintCarriesItsVersion(t *testing.T) {
	// Changing the inputs without changing the version would make every
	// finding look new with no way to tell why, so the version is mixed in and
	// the SARIF key names it.
	a := scanWith("/repo", []Finding{{RuleID: "R", File: "/repo/a", Code: "x"}}, nil, nil)
	if a.SASTFindings[0].Fingerprint == "" {
		t.Fatal("no fingerprint assigned")
	}
	if FingerprintVersion == "" {
		t.Error("the scheme has no version to advertise")
	}
}

func TestLeakFingerprint(t *testing.T) {
	t.Run("the redacted match identifies the secret", func(t *testing.T) {
		same := scanWith("/repo", nil, []LeakFinding{
			{RuleID: "LEAK-001", File: "/repo/.env", Line: 3, Match: "AKIA****WXYZ"},
		}, nil)
		moved := scanWith("/repo", nil, []LeakFinding{
			{RuleID: "LEAK-001", File: "/repo/.env", Line: 31, Match: "AKIA****WXYZ"},
		}, nil)
		if same.LeakFindings[0].Fingerprint != moved.LeakFindings[0].Fingerprint {
			t.Error("the secret moved down the file and changed identity")
		}

		other := scanWith("/repo", nil, []LeakFinding{
			{RuleID: "LEAK-001", File: "/repo/.env", Line: 3, Match: "AKIA****ABCD"},
		}, nil)
		if same.LeakFindings[0].Fingerprint == other.LeakFindings[0].Fingerprint {
			t.Error("a different secret in the same place shares an identity")
		}
	})

	t.Run("a secret in history is not the same finding", func(t *testing.T) {
		// One is fixed by editing the file; the other needs the history
		// rewritten and the credential rotated. Sharing an identity would let
		// resolving one silently close the other.
		working := scanWith("/repo", nil, []LeakFinding{
			{RuleID: "LEAK-001", File: "/repo/.env", Match: "AKIA****WXYZ"},
		}, nil)
		historical := scanWith("/repo", nil, []LeakFinding{
			{RuleID: "LEAK-001", File: "/repo/.env", Match: "AKIA****WXYZ", CommitHash: "9f2c1ab"},
		}, nil)
		if working.LeakFindings[0].Fingerprint == historical.LeakFindings[0].Fingerprint {
			t.Error("a committed secret and a working-tree secret share an identity")
		}
	})
}

func TestSCAFingerprint(t *testing.T) {
	base := SCAFinding{
		Ecosystem: "npm", PackageName: "lodash", PackageVersion: "4.17.15",
		ManifestFile: "/repo/package-lock.json", CVE: "CVE-2021-23337",
	}

	t.Run("the same advisory in the same manifest keeps its identity", func(t *testing.T) {
		a := scanWith("/repo", nil, nil, []SCAFinding{base})
		b := scanWith("/repo", nil, nil, []SCAFinding{base})
		if a.SCAFindings[0].Fingerprint != b.SCAFindings[0].Fingerprint {
			t.Error("two scans of one finding disagree")
		}
	})

	t.Run("upgrading the package is a different finding", func(t *testing.T) {
		// The identity has to change: the alert against 4.17.15 is resolved,
		// and whatever is reported against the new version is a new alert.
		upgraded := base
		upgraded.PackageVersion = "4.17.21"

		a := scanWith("/repo", nil, nil, []SCAFinding{base})
		b := scanWith("/repo", nil, nil, []SCAFinding{upgraded})
		if a.SCAFindings[0].Fingerprint == b.SCAFindings[0].Fingerprint {
			t.Error("a version bump left the identity unchanged")
		}
	})

	t.Run("one package vulnerable in two manifests is two findings", func(t *testing.T) {
		other := base
		other.ManifestFile = "/repo/api/package-lock.json"

		result := scanWith("/repo", nil, nil, []SCAFinding{base, other})
		if result.SCAFindings[0].Fingerprint == result.SCAFindings[1].Fingerprint {
			t.Error("two projects of a monorepo share one identity")
		}
	})

	t.Run("an advisory with no CVE falls back to its URL", func(t *testing.T) {
		ghsaOnly := base
		ghsaOnly.CVE = ""
		ghsaOnly.Advisory = "https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc"
		another := ghsaOnly
		another.Advisory = "https://osv.dev/vulnerability/GHSA-dddd-eeee-ffff"

		result := scanWith("/repo", nil, nil, []SCAFinding{ghsaOnly, another})
		if result.SCAFindings[0].Fingerprint == result.SCAFindings[1].Fingerprint {
			t.Error("two different GHSA-only advisories collapsed into one identity")
		}
	})
}

// TestFingerprintKindsDoNotCollide guards the one thing hashing a joined string
// makes easy to get wrong: a SAST finding and a leak finding whose inputs
// happen to line up.
func TestFingerprintKindsDoNotCollide(t *testing.T) {
	result := scanWith("/repo",
		[]Finding{{RuleID: "LEAK-001", File: "/repo/.env", Code: "AKIA****WXYZ"}},
		[]LeakFinding{{RuleID: "LEAK-001", File: "/repo/.env", Match: "AKIA****WXYZ"}},
		nil,
	)
	if result.SASTFindings[0].Fingerprint == result.LeakFindings[0].Fingerprint {
		t.Error("a SAST finding and a leak finding share an identity")
	}
}

func TestFingerprintShape(t *testing.T) {
	result := scanWith("/repo", []Finding{
		{RuleID: "PY-001", File: "/repo/a.py", Code: "x", Severity: config.SeverityHigh},
	}, nil, nil)

	got := result.SASTFindings[0].Fingerprint
	if len(got) != 16 {
		t.Errorf("fingerprint %q is %d characters, want 16", got, len(got))
	}
	if strings.Trim(got, "0123456789abcdef") != "" {
		t.Errorf("fingerprint %q is not hexadecimal", got)
	}
}
