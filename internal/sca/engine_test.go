package sca

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// writeManifest creates a manifest file inside a fresh temporary directory and
// returns its path.
func writeManifest(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

// depNames returns the parsed names, sorted, so assertions do not depend on
// map iteration order.
func depNames(deps []Dependency) []string {
	names := make([]string, 0, len(deps))
	for _, d := range deps {
		names = append(names, d.Name)
	}
	sort.Strings(names)
	return names
}

// findDep looks up a parsed dependency by name.
func findDep(deps []Dependency, name string) (Dependency, bool) {
	for _, d := range deps {
		if d.Name == name {
			return d, true
		}
	}
	return Dependency{}, false
}

func TestPackageJSONParser(t *testing.T) {
	path := writeManifest(t, "package.json", `{
	  "name": "app",
	  "dependencies": {
	    "express": "^4.18.2",
	    "lodash": "4.17.15"
	  },
	  "devDependencies": {
	    "jest": "~29.7.0"
	  }
	}`)

	deps, err := (&PackageJSONParser{}).Parse(path)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	want := []string{"express", "jest", "lodash"}
	if got := depNames(deps); !equalStrings(got, want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}

	// Range operators must be stripped so the version can be matched against
	// an advisory database.
	express, _ := findDep(deps, "express")
	if express.Version != "4.18.2" {
		t.Errorf("express version = %q, want %q", express.Version, "4.18.2")
	}
	if express.Ecosystem != "npm" {
		t.Errorf("express ecosystem = %q, want %q", express.Ecosystem, "npm")
	}
	jest, _ := findDep(deps, "jest")
	if jest.Version != "29.7.0" {
		t.Errorf("jest version = %q, want %q", jest.Version, "29.7.0")
	}
}

func TestPackageJSONParserRejectsMalformedJSON(t *testing.T) {
	path := writeManifest(t, "package.json", `{"dependencies": {`)
	if _, err := (&PackageJSONParser{}).Parse(path); err == nil {
		t.Error("Parse succeeded on malformed JSON, want an error")
	}
}

func TestRequirementsTXTParser(t *testing.T) {
	path := writeManifest(t, "requirements.txt", strings.Join([]string{
		"# comment line",
		"",
		"-r other-requirements.txt",
		"django==4.0.3",
		"requests>=2.27.0",
		"pillow~=9.0.0",
		"urllib3>=1.26.0,<2.0.0",
	}, "\n"))

	deps, err := (&RequirementsTXTParser{}).Parse(path)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	want := []string{"django", "pillow", "requests", "urllib3"}
	if got := depNames(deps); !equalStrings(got, want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}

	django, _ := findDep(deps, "django")
	if django.Version != "4.0.3" {
		t.Errorf("django version = %q, want %q", django.Version, "4.0.3")
	}
	if django.Ecosystem != "pypi" {
		t.Errorf("django ecosystem = %q, want %q", django.Ecosystem, "pypi")
	}
	// A compound specifier keeps only the lower bound.
	urllib3, _ := findDep(deps, "urllib3")
	if urllib3.Version != "1.26.0" {
		t.Errorf("urllib3 version = %q, want %q", urllib3.Version, "1.26.0")
	}
}

// TestRequirementsTXTParserStripsMarkersAndComments covers the two suffixes pip
// allows after a version: an environment marker and a trailing comment. Both
// have to come off, otherwise the version carries prose into the OSV query and
// never matches an advisory.
func TestRequirementsTXTParserStripsMarkersAndComments(t *testing.T) {
	path := writeManifest(t, "requirements.txt", strings.Join([]string{
		`requests==2.31.0 ; python_version < "3.12"`,
		"flask==2.0.1  # pinned for the legacy API",
	}, "\n"))

	deps, err := (&RequirementsTXTParser{}).Parse(path)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	requests, ok := findDep(deps, "requests")
	if !ok {
		t.Fatal("requests was not parsed")
	}
	if requests.Version != "2.31.0" {
		t.Errorf("requests version = %q, want %q — the environment marker leaked "+
			"into the version", requests.Version, "2.31.0")
	}

	flask, ok := findDep(deps, "flask")
	if !ok {
		t.Fatal("flask was not parsed")
	}
	if flask.Version != "2.0.1" {
		t.Errorf("flask version = %q, want %q — the trailing comment leaked into "+
			"the version", flask.Version, "2.0.1")
	}
}

func TestGoModParser(t *testing.T) {
	path := writeManifest(t, "go.mod", strings.Join([]string{
		"module github.com/example/app",
		"",
		"go 1.26.5",
		"",
		"require (",
		"\tgithub.com/fatih/color v1.19.0",
		"\tgithub.com/spf13/cobra v1.10.2",
		"\tgolang.org/x/sys v0.28.0 // indirect",
		")",
	}, "\n"))

	deps, err := (&GoModParser{}).Parse(path)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	want := []string{"github.com/fatih/color", "github.com/spf13/cobra", "golang.org/x/sys"}
	if got := depNames(deps); !equalStrings(got, want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}

	color, _ := findDep(deps, "github.com/fatih/color")
	if color.Version != "v1.19.0" {
		t.Errorf("color version = %q, want %q", color.Version, "v1.19.0")
	}
	// The "// indirect" marker must not end up in the version.
	sys, _ := findDep(deps, "golang.org/x/sys")
	if sys.Version != "v0.28.0" {
		t.Errorf("sys version = %q, want %q", sys.Version, "v0.28.0")
	}
	if sys.Ecosystem != "go" {
		t.Errorf("sys ecosystem = %q, want %q", sys.Ecosystem, "go")
	}
}

func TestGoModParserSingleLineRequire(t *testing.T) {
	path := writeManifest(t, "go.mod", strings.Join([]string{
		"module github.com/example/app",
		"",
		"require github.com/fatih/color v1.19.0",
	}, "\n"))

	deps, err := (&GoModParser{}).Parse(path)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(deps) != 1 || deps[0].Name != "github.com/fatih/color" {
		t.Fatalf("parsed %v, want a single github.com/fatih/color entry", depNames(deps))
	}
}

// TestGemfileLockParserIgnoresTheDependenciesSection pins the shape of a
// Gemfile.lock: only the GEM specs section lists resolved versions. The
// DEPENDENCIES section repeats the same gems with range constraints, and
// reading a constraint as a version produces entries like rails "~>", which
// are inventory noise and match no advisory.
func TestGemfileLockParserIgnoresTheDependenciesSection(t *testing.T) {
	path := writeManifest(t, "Gemfile.lock", strings.Join([]string{
		"GEM",
		"  remote: https://rubygems.org/",
		"  specs:",
		"    rack (2.2.8)",
		"    rails (7.1.0)",
		// Six-space lines are the gem's own requirements, carrying an
		// operator instead of a resolved version.
		"      actionpack (= 7.1.0)",
		"      activerecord (>= 7.0)",
		"",
		"PLATFORMS",
		"  ruby",
		"",
		"DEPENDENCIES",
		"  rails (~> 7.1.0)",
		"",
		"BUNDLED WITH",
		"   2.4.10",
	}, "\n"))

	deps, err := (&GemfileParser{}).Parse(path)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	want := []string{"rack", "rails"}
	if got := depNames(deps); !equalStrings(got, want) {
		t.Fatalf("parsed %v, want exactly %v", got, want)
	}

	rails, _ := findDep(deps, "rails")
	if rails.Version != "7.1.0" {
		t.Errorf("rails version = %q, want the resolved version %q", rails.Version, "7.1.0")
	}
	if rails.Ecosystem != "rubygems" {
		t.Errorf("rails ecosystem = %q, want %q", rails.Ecosystem, "rubygems")
	}
}

func TestComposerParser(t *testing.T) {
	path := writeManifest(t, "composer.json", `{
	  "require": {
	    "php": ">=8.1",
	    "monolog/monolog": "^2.9.1"
	  },
	  "require-dev": {
	    "phpunit/phpunit": "10.5.0"
	  }
	}`)

	deps, err := (&ComposerParser{}).Parse(path)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	// "php" is the language runtime, not a package.
	want := []string{"monolog/monolog", "phpunit/phpunit"}
	if got := depNames(deps); !equalStrings(got, want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}

	monolog, _ := findDep(deps, "monolog/monolog")
	if monolog.Version != "2.9.1" {
		t.Errorf("monolog version = %q, want %q", monolog.Version, "2.9.1")
	}
	if monolog.Ecosystem != "packagist" {
		t.Errorf("monolog ecosystem = %q, want %q", monolog.Ecosystem, "packagist")
	}
}

func TestPubspecParser(t *testing.T) {
	path := writeManifest(t, "pubspec.yaml", strings.Join([]string{
		"name: example_app",
		"dependencies:",
		"  flutter:",
		"    sdk: flutter",
		"  http: ^1.2.0",
		"dev_dependencies:",
		"  test: 1.24.0",
	}, "\n"))

	deps, err := (&PubspecParser{}).Parse(path)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	// "flutter" is the SDK itself and carries a map, not a version.
	want := []string{"http", "test"}
	if got := depNames(deps); !equalStrings(got, want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}

	httpDep, _ := findDep(deps, "http")
	if httpDep.Version != "1.2.0" {
		t.Errorf("http version = %q, want %q", httpDep.Version, "1.2.0")
	}
	if httpDep.Ecosystem != "pub" {
		t.Errorf("http ecosystem = %q, want %q", httpDep.Ecosystem, "pub")
	}
}

func TestPomXMLParser(t *testing.T) {
	path := writeManifest(t, "pom.xml", strings.Join([]string{
		"<project>",
		"  <dependencies>",
		"    <dependency>",
		"      <groupId>org.apache.logging.log4j</groupId>",
		"      <artifactId>log4j-core</artifactId>",
		"      <version>2.14.1</version>",
		"    </dependency>",
		"    <dependency>",
		"      <artifactId>property-driven</artifactId>",
		"      <version>${spring.version}</version>",
		"    </dependency>",
		"  </dependencies>",
		"</project>",
	}, "\n"))

	deps, err := (&PomXMLParser{}).Parse(path)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	// A ${...} placeholder is not a resolvable version, so it is skipped.
	if got := depNames(deps); !equalStrings(got, []string{"log4j-core"}) {
		t.Fatalf("parsed %v, want [log4j-core]", got)
	}
	log4j, _ := findDep(deps, "log4j-core")
	if log4j.Version != "2.14.1" {
		t.Errorf("log4j-core version = %q, want %q", log4j.Version, "2.14.1")
	}
}

func TestStripVersionPrefix(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"^4.18.2", "4.18.2"},
		{"~29.7.0", "29.7.0"},
		{">=2.27.0", "2.27.0"},
		{"<=1.0.0", "1.0.0"},
		{"==1.0.0", "1.0.0"},
		{"!=1.0.0", "1.0.0"},
		{"~>7.1.0", "7.1.0"},
		{">1.0.0", "1.0.0"},
		{"<1.0.0", "1.0.0"},
		{"=1.0.0", "1.0.0"},
		{"  4.17.15  ", "4.17.15"},
		{"4.17.15", "4.17.15"},
		// Only one operator comes off: collapsing "^>=1.0" to "1.0" would
		// silently reinterpret the constraint.
		{"^>=1.0", ">=1.0"},
	}

	for _, tt := range tests {
		if got := stripVersionPrefix(tt.in); got != tt.want {
			t.Errorf("stripVersionPrefix(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestReadManifestFileRejectsOversizedManifests(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")
	// One byte past the cap is enough to prove the guard fires.
	if err := os.WriteFile(path, make([]byte, maxManifestSize+1), 0o600); err != nil {
		t.Fatalf("writing oversized manifest: %v", err)
	}

	_, err := readManifestFile(path)
	if err == nil {
		t.Fatal("readManifestFile accepted a manifest over the size cap, want an error")
	}
	if !strings.Contains(err.Error(), "refusing to parse") {
		t.Errorf("error = %q, want it to explain the refusal", err)
	}
}

func TestReadManifestFileMissing(t *testing.T) {
	if _, err := readManifestFile(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Error("readManifestFile succeeded on a missing file, want an error")
	}
}

// TestEngineCollectsAcrossEcosystemsAndSkipsVendorDirs exercises the engine
// end to end over a tree with several manifests, including one inside an
// ignored directory.
func TestEngineCollectsAcrossEcosystemsAndSkipsVendorDirs(t *testing.T) {
	root := t.TempDir()

	mustWrite := func(rel, content string) {
		t.Helper()
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("creating %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", rel, err)
		}
	}

	mustWrite("package.json", `{"dependencies":{"express":"4.18.2"}}`)
	mustWrite("api/requirements.txt", "django==4.0.3\n")
	mustWrite("node_modules/inner/package.json", `{"dependencies":{"should-not-appear":"1.0.0"}}`)

	engine := New(root)
	deps, err := engine.collectDependencies()
	if err != nil {
		t.Fatalf("collectDependencies returned error: %v", err)
	}

	want := []string{"django", "express"}
	if got := depNames(deps); !equalStrings(got, want) {
		t.Fatalf("collected %v, want %v — dependencies inside node_modules are "+
			"not the project's own", got, want)
	}
}

func TestEngineDependenciesReturnsTheFullInventory(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"),
		[]byte(`{"dependencies":{"express":"4.18.2","lodash":"4.17.15"}}`), 0o600); err != nil {
		t.Fatalf("writing package.json: %v", err)
	}

	engine := New(root)
	// Dependencies() reflects the last collection, which the SBOM writer reads
	// to list every component and not only the vulnerable ones.
	deps, err := engine.collectDependencies()
	if err != nil {
		t.Fatalf("collectDependencies returned error: %v", err)
	}
	engine.lastDeps = deps

	if got := depNames(engine.Dependencies()); !equalStrings(got, []string{"express", "lodash"}) {
		t.Errorf("Dependencies() = %v, want both components", got)
	}
}

func TestCountUniqueFiles(t *testing.T) {
	e := &Engine{}
	deps := []Dependency{
		{Name: "a", File: "package.json"},
		{Name: "b", File: "package.json"},
		{Name: "c", File: "api/requirements.txt"},
	}
	if got := e.countUniqueFiles(deps); got != 2 {
		t.Errorf("countUniqueFiles() = %d, want 2", got)
	}
}

func TestCheckKnownVulnerabilitiesMatchesOnExactVersion(t *testing.T) {
	e := &Engine{}

	findings := e.checkKnownVulnerabilities([]Dependency{
		{Name: "log4j-core", Version: "2.14.1", Ecosystem: "maven", File: "pom.xml"},
		// Same package, a version that is not affected.
		{Name: "log4j-core", Version: "2.17.1", Ecosystem: "maven", File: "pom.xml"},
	})

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (only the affected version)", len(findings))
	}
	f := findings[0]
	if f.CVE != "CVE-2021-44228" {
		t.Errorf("CVE = %q, want %q", f.CVE, "CVE-2021-44228")
	}
	if f.FixedVersion != "2.17.1" {
		t.Errorf("FixedVersion = %q, want %q", f.FixedVersion, "2.17.1")
	}
}

func TestExtractXMLTag(t *testing.T) {
	tests := []struct {
		line, tag, want string
	}{
		{"  <artifactId>log4j-core</artifactId>", "artifactId", "log4j-core"},
		{"<version> 2.14.1 </version>", "version", "2.14.1"},
		{"<artifactId>unclosed", "artifactId", ""},
		{"nothing here", "version", ""},
	}

	for _, tt := range tests {
		if got := extractXMLTag(tt.line, tt.tag); got != tt.want {
			t.Errorf("extractXMLTag(%q, %q) = %q, want %q", tt.line, tt.tag, got, tt.want)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
