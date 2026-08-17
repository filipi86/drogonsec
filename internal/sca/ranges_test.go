package sca

import (
	"path/filepath"
	"testing"
)

// TestPinnedVersion pins the one distinction the advisory match rests on.
//
// The bare form is the interesting column: "1.2.3" names a single release
// everywhere except Cargo, where it is shorthand for "^1.2.3". Getting that
// backwards for one ecosystem either drops every Cargo.toml finding or restores
// the false positives for everything else.
func TestPinnedVersion(t *testing.T) {
	tests := []struct {
		spec      string
		bareIsPin bool
		version   string
		pinned    bool
	}{
		// Pins.
		{"1.2.3", true, "1.2.3", true},
		{"==2.27.0", true, "2.27.0", true},
		{"=1.0.130", false, "1.0.130", true},
		{"v6.4.43", true, "v6.4.43", true},
		{" 1.2.3 ", true, "1.2.3", true},

		// Ranges: the version is still reported, but not matched.
		{"^4.17.15", true, "4.17.15", false},
		{"~1.2.3", true, "1.2.3", false},
		{">=3.2.12", true, "3.2.12", false},
		{"<2.0.0", true, "2.0.0", false},
		{"~>2.1", true, "2.1", false},

		// Cargo reads a bare version as a caret range.
		{"1.0.130", false, "1.0.130", false},
		{"1.0", false, "1.0", false},

		// Compound requirements are ranges whatever their parts look like.
		{"^1.0 || ^2.0", true, "1.0 || ^2.0", false},
		{">=1.2,<2", true, "1.2,<2", false},
		{"1.2 - 1.5", true, "1.2 - 1.5", false},

		// Not versions at all.
		{"*", true, "*", false},
		{"1.2.x", true, "1.2.x", false},
		{"latest", true, "latest", false},
		{"workspace:*", true, "workspace:*", false},
		{"file:../lib", true, "file:../lib", false},
		{"git+https://example.test/x.git", true, "git+https://example.test/x.git", false},
		{"", true, "", false},
	}

	for _, tt := range tests {
		version, pinned := pinnedVersion(tt.spec, tt.bareIsPin)
		if version != tt.version || pinned != tt.pinned {
			t.Errorf("pinnedVersion(%q, bareIsPin=%v) = (%q, %v), want (%q, %v)",
				tt.spec, tt.bareIsPin, version, pinned, tt.version, tt.pinned)
		}
	}
}

// TestManifestRangesAreNotMatchedAgainstAdvisories is the regression this whole
// change exists for.
//
// "^4.17.15" is how almost every npm dependency is written. It installs lodash
// 4.17.21, where three of the six advisories against 4.17.15 are fixed — so
// querying the number after the caret reported flaws in code that does not
// ship, against a version the project never installed.
func TestManifestRangesAreNotMatchedAgainstAdvisories(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"package.json": `{"name":"app","dependencies":{
		  "lodash": "^4.17.15",
		  "express": "4.17.1",
		  "moment": "~2.29.1",
		  "left-pad": "*"
		}}`,
	})

	deps, err := (&PackageJSONParser{}).Parse(filepath.Join(dir, "package.json"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	ranged := map[string]bool{
		"lodash":   true,
		"express":  false, // an exact pin is still answerable
		"moment":   true,
		"left-pad": true,
	}
	for _, d := range deps {
		if d.VersionIsRange != ranged[d.Name] {
			t.Errorf("%s %q VersionIsRange = %v, want %v", d.Name, d.Version, d.VersionIsRange, ranged[d.Name])
		}
	}

	t.Run("everything stays in the inventory", func(t *testing.T) {
		// The SBOM has to list what the project depends on either way. Dropping
		// the ranged packages entirely would trade a false positive for a
		// component inventory that is quietly incomplete.
		if len(deps) != 4 {
			t.Errorf("parsed %d dependencies, want all 4: %v", len(deps), depNames(deps))
		}
	})

	t.Run("only the pinned one reaches the advisory query", func(t *testing.T) {
		// checkKnownVulnerabilities holds lodash 4.17.15 and express 4.17.1.
		// Before this change both were reported; only express is answerable.
		findings := (&Engine{}).checkKnownVulnerabilities(deps)
		for _, f := range findings {
			if f.PackageName != "express" {
				t.Errorf("%s@%s was matched from a range", f.PackageName, f.PackageVersion)
			}
		}
		if len(findings) == 0 {
			t.Error("the pinned express 4.17.1 should still be matched")
		}
	})
}

// TestRequirementsRangesAreNotMatched covers pip, where "==" is the pin and
// every other operator names a span. A lower bound is the trap: "django>=3.2.12"
// is satisfied by 5.x, where the advisories against 3.2.12 are long fixed.
func TestRequirementsRangesAreNotMatched(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"requirements.txt": `
requests==2.27.0
django>=3.2.12
pillow~=9.0.0
urllib3==2.0.*,!=2.0.1
celery==5.2.0 ; python_version >= "3.8"
`,
	})

	deps, err := (&RequirementsTXTParser{}).Parse(filepath.Join(dir, "requirements.txt"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	ranged := map[string]bool{
		"requests": false,
		"django":   true,
		"pillow":   true,
		// A second specifier makes it a span even though the first operator is "==".
		"urllib3": true,
		// An environment marker is not a second specifier; the pin still holds.
		"celery": false,
	}
	for _, d := range deps {
		if d.VersionIsRange != ranged[d.Name] {
			t.Errorf("%s %q VersionIsRange = %v, want %v", d.Name, d.Version, d.VersionIsRange, ranged[d.Name])
		}
	}
}

// TestCargoManifestBareVersionIsARange guards the inverted rule. `serde = "1.0"`
// is a caret range in Cargo, so the one manifest that looks most like a pin is
// the one that is not.
func TestCargoManifestBareVersionIsARange(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"Cargo.toml": `
[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "1.0.130"
time = "=0.3.9"
smallvec = { version = "1.6.0", features = ["union"] }
`,
	})

	deps, err := (&CargoTOMLParser{}).Parse(filepath.Join(dir, "Cargo.toml"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	ranged := map[string]bool{
		"serde":    true,  // bare, so a caret range
		"time":     false, // "=" is Cargo's pin
		"smallvec": true,  // bare inside a table is still bare
	}
	for _, d := range deps {
		if d.VersionIsRange != ranged[d.Name] {
			t.Errorf("%s %q VersionIsRange = %v, want %v", d.Name, d.Version, d.VersionIsRange, ranged[d.Name])
		}
	}
}

// TestLockfileVersionsAreNeverRanges is the other half of the guarantee. A
// lockfile states what was resolved, so nothing it produces may be excluded
// from the advisory query — the zero value of the field has to mean "pinned",
// or adding a lockfile parser would silently disable its findings.
func TestLockfileVersionsAreNeverRanges(t *testing.T) {
	for _, fixture := range []struct {
		dir, file string
		parser    ManifestParser
	}{
		{composerFixture, "composer.lock", &ComposerLockParser{}},
		{cargoFixture, "Cargo.lock", &CargoLockParser{}},
		{poetryFixture, "poetry.lock", &PoetryLockParser{}},
	} {
		deps, err := fixture.parser.Parse(filepath.Join(fixture.dir, fixture.file))
		if err != nil {
			t.Fatalf("%s: Parse returned error: %v", fixture.file, err)
		}
		if len(deps) == 0 {
			t.Fatalf("%s: parsed nothing", fixture.file)
		}
		for _, d := range deps {
			if d.VersionIsRange {
				t.Errorf("%s: %s@%s came from a lockfile and must be matchable", fixture.file, d.Name, d.Version)
			}
		}
	}
}
