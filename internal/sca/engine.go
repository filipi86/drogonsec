package sca

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/filipi86/drogonsec/internal/config"
	"github.com/filipi86/drogonsec/internal/ui"
	"gopkg.in/yaml.v3"
)

// Finding mirrors analyzer.SCAFinding to avoid import cycle
type Finding struct {
	PackageName    string
	PackageVersion string
	FixedVersion   string
	Ecosystem      string
	ManifestFile   string
	Severity       config.Severity
	CVE            string
	CVSS           float64
	Description    string
	Advisory       string
	OWASP          config.OWASPCategory

	// Direct and DependencyPath carry the shape of the dependency graph
	// through to the report. They are what turns "you have 340 vulnerabilities"
	// into something a team can act on: a vulnerability in a package the
	// project never named is not fixed by upgrading that package, it is fixed —
	// if at all — by moving whatever pulled it in.
	//
	// analyzer.SCAFinding is converted from this type directly, so the two
	// declarations have to stay field-for-field identical.
	Direct         bool
	DependencyPath []string
}

// Dependency represents a parsed dependency
type Dependency struct {
	Name      string
	Version   string
	Ecosystem string
	File      string

	// Direct records whether the project declares this dependency itself.
	// Everything else arrived because something else asked for it, which is
	// where most vulnerabilities live and where the fix is rarely a version
	// bump of the package named in the advisory.
	Direct bool

	// Path is the chain of packages that introduces a transitive dependency,
	// from a direct dependency inwards and excluding the dependency itself:
	// ["express", "cookie"] means express depends on cookie which depends on
	// this one. Empty for a direct dependency, and empty when the route cannot
	// be established. It answers the first question anyone asks about an
	// advisory in a package they have never heard of.
	Path []string
}

// ManifestParser defines the interface for manifest file parsers
type ManifestParser interface {
	Name() string
	Files() []string
	Parse(filePath string) ([]Dependency, error)
}

// Engine performs Software Composition Analysis
type Engine struct {
	targetPath string
	parsers    []ManifestParser
	lastDeps   []Dependency
}

// New creates a new SCA Engine
func New(targetPath string) *Engine {
	e := &Engine{targetPath: targetPath}
	e.registerParsers()
	return e
}

// registerParsers adds all manifest parsers
func (e *Engine) registerParsers() {
	e.parsers = []ManifestParser{
		&PackageLockParser{},
		&YarnLockParser{},
		&PackageJSONParser{},
		&PomXMLParser{},
		&RequirementsTXTParser{},
		&GemfileParser{},
		&GoModParser{},
		&ComposerParser{},
		&PubspecParser{},
	}
}

// Analyze performs SCA on the target path
func (e *Engine) Analyze() ([]Finding, error) {
	deps, err := e.collectDependencies()
	if err != nil {
		return nil, fmt.Errorf("dependency collection failed: %w", err)
	}
	// Retain the full inventory so callers can build an SBOM (all components,
	// not only the vulnerable ones) without re-walking the tree.
	e.lastDeps = deps

	if len(deps) == 0 {
		return nil, nil
	}

	ui.Printf("  Found %d dependencies across %d manifest files\n", len(deps), e.countUniqueFiles(deps))

	// Query OSV API for real vulnerability data, fall back to demo DB on error
	osv := newOSVClient()
	findings, err := osv.QueryBatch(deps)
	if err != nil {
		ui.Printf("  OSV API unavailable (%v), falling back to local database\n", err)
		findings = e.checkKnownVulnerabilities(deps)
	}

	return dedupeFindings(findings), nil
}

// dedupeFindings collapses records that describe the same vulnerability in the
// same package.
//
// OSV frequently holds one flaw under several identifiers that alias each
// other — path-to-regexp 0.1.7 comes back as both GHSA-37ch-88jc-xwx2 and
// GHSA-9wv6-86v2-598j, each listing the other and both resolving to
// CVE-2024-45296. Reporting that twice inflates the count and costs a reviewer
// the time it takes to work out the two entries are one issue.
//
// A CVE identifies the flaw, so it is the key wherever there is one. Advisories
// that never received a CVE fall back to their advisory URL, which keeps two
// genuinely different GHSA-only records apart. The manifest is part of the key
// so that the same package vulnerable in two projects of a monorepo is still
// reported for each.
func dedupeFindings(findings []Finding) []Finding {
	seen := make(map[string]bool, len(findings))
	kept := make([]Finding, 0, len(findings))

	for _, f := range findings {
		identity := f.CVE
		if identity == "" {
			identity = f.Advisory
		}
		key := strings.Join([]string{f.Ecosystem, f.PackageName, f.PackageVersion, f.ManifestFile, identity}, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		kept = append(kept, f)
	}

	return kept
}

// Dependencies returns the full set of dependencies discovered by the most
// recent Analyze call. It is the component inventory used to build an SBOM,
// independent of whether each dependency is vulnerable.
func (e *Engine) Dependencies() []Dependency {
	return e.lastDeps
}

// collectDependencies finds and parses all manifest files.
//
// Where a lockfile and a manifest describe the same project, only the lockfile
// is kept: it names every installed package at the version actually installed,
// while the manifest repeats the handful the project declared, at a range.
// Merging the two would report the same direct dependency twice and match the
// second copy against a range like "^4.17.1", which is neither a version that
// exists nor one an advisory can be checked against.
func (e *Engine) collectDependencies() ([]Dependency, error) {
	var lockfileDeps, manifestDeps []Dependency

	// Directories where a lockfile has already spoken for an ecosystem.
	locked := make(map[string]bool)

	for _, parser := range e.parsers {
		_, isLockfile := parser.(LockfileParser)

		for _, manifestName := range parser.Files() {
			err := filepath.WalkDir(e.targetPath, func(path string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}

				// Skip ignored directories
				for _, ignore := range config.DefaultIgnorePaths {
					if strings.Contains(path, "/"+ignore+"/") || strings.HasSuffix(path, "/"+ignore) {
						return filepath.SkipDir
					}
				}

				if filepath.Base(path) != manifestName {
					return nil
				}

				deps, parseErr := parser.Parse(path)
				if parseErr != nil {
					return nil
				}

				if isLockfile {
					// A project can carry two lockfiles for one ecosystem — a
					// package-lock.json left behind beside a yarn.lock is the
					// common case, usually after a migration. They describe one
					// installation, so taking both reports every package twice.
					// The parser registered first wins, which makes the choice
					// deterministic rather than dependent on directory order.
					skip := make(map[string]bool, 1)
					for _, dep := range deps {
						key := lockKey(path, dep.Ecosystem)
						if _, decided := skip[key]; !decided {
							skip[key] = locked[key]
							locked[key] = true
						}
					}
					for _, dep := range deps {
						if !skip[lockKey(path, dep.Ecosystem)] {
							lockfileDeps = append(lockfileDeps, dep)
						}
					}
					return nil
				}

				// A manifest states intent, so everything it lists is by
				// definition declared by the project. Lockfile parsers work the
				// direct/transitive split out for themselves.
				for i := range deps {
					deps[i].Direct = true
				}
				manifestDeps = append(manifestDeps, deps...)
				return nil
			})
			if err != nil {
				continue
			}
		}
	}

	// Second source of truth, for projects that do not commit a lockfile: the
	// tree already installed on disk. It is read only where no lockfile spoke,
	// because a lockfile describes what will be installed reproducibly, while
	// node_modules describes one machine's current state — which may be stale,
	// and is absent altogether until somebody runs an install.
	for _, dir := range npmProjectDirs(manifestDeps) {
		key := lockKey(filepath.Join(dir, "package.json"), "npm")
		if locked[key] {
			continue
		}
		installed, err := parseInstalledNodeModules(dir)
		if err != nil || len(installed) == 0 {
			continue
		}
		locked[key] = true
		lockfileDeps = append(lockfileDeps, installed...)
	}

	for _, dep := range manifestDeps {
		if locked[lockKey(dep.File, dep.Ecosystem)] {
			continue
		}
		lockfileDeps = append(lockfileDeps, dep)
	}

	return lockfileDeps, nil
}

// lockKey identifies an ecosystem within one project directory.
func lockKey(manifestPath, ecosystem string) string {
	return filepath.Dir(manifestPath) + "\x00" + ecosystem
}

// countUniqueFiles returns the number of unique manifest files
func (e *Engine) countUniqueFiles(deps []Dependency) int {
	files := make(map[string]bool)
	for _, d := range deps {
		files[d.File] = true
	}
	return len(files)
}

// checkKnownVulnerabilities simulates checking against a vulnerability DB
// In production, this would make API calls to OSV.dev or NVD
func (e *Engine) checkKnownVulnerabilities(deps []Dependency) []Finding {
	var findings []Finding

	// Known vulnerable packages (example database - would be replaced by OSV API)
	knownVulnerable := map[string][]struct {
		version  string
		cve      string
		severity config.Severity
		cvss     float64
		fixed    string
		desc     string
	}{
		"log4j-core": {
			{"2.14.1", "CVE-2021-44228", config.SeverityCritical, 10.0, "2.17.1",
				"Log4Shell: Remote code execution via JNDI lookup in log messages"},
			{"2.14.0", "CVE-2021-44228", config.SeverityCritical, 10.0, "2.17.1",
				"Log4Shell: Remote code execution via JNDI lookup"},
		},
		"lodash": {
			{"4.17.15", "CVE-2021-23337", config.SeverityHigh, 7.2, "4.17.21",
				"Command injection via template function"},
			{"4.17.19", "CVE-2020-28500", config.SeverityMedium, 5.3, "4.17.21",
				"Regular expression DoS (ReDoS) vulnerability"},
		},
		"node-fetch": {
			{"2.6.0", "CVE-2022-0235", config.SeverityHigh, 8.8, "2.6.7",
				"Exposure of sensitive information to unauthorized actors"},
		},
		"express": {
			{"4.17.1", "CVE-2022-24999", config.SeverityHigh, 7.5, "4.18.2",
				"Open redirect vulnerability in express.static"},
		},
		"django": {
			{"3.2.12", "CVE-2022-28347", config.SeverityHigh, 9.8, "3.2.13",
				"SQL injection via QuerySet.explain() on MySQL"},
			{"4.0.3", "CVE-2022-28347", config.SeverityHigh, 9.8, "4.0.4",
				"SQL injection vulnerability"},
		},
		"struts2-core": {
			{"2.3.34", "CVE-2017-5638", config.SeverityCritical, 10.0, "2.3.35",
				"RCE via Jakarta Multipart parser (Equifax breach vector)"},
		},
		"jackson-databind": {
			{"2.9.8", "CVE-2019-14379", config.SeverityCritical, 9.8, "2.9.9.3",
				"Deserialization flaw allows remote code execution"},
		},
		"requests": {
			{"2.27.0", "CVE-2023-32681", config.SeverityMedium, 6.1, "2.31.0",
				"Unintended leak of Proxy-Authorization header"},
		},
		"pillow": {
			{"9.0.0", "CVE-2023-44271", config.SeverityMedium, 7.5, "10.0.1",
				"Uncontrolled resource consumption in PIL.ImageFont"},
		},
		"moment": {
			{"2.29.1", "CVE-2022-24785", config.SeverityHigh, 7.5, "2.29.2",
				"Path traversal vulnerability"},
			{"2.29.3", "CVE-2022-31129", config.SeverityHigh, 7.5, "2.29.4",
				"ReDoS vulnerability in parsing logic"},
		},
	}

	for _, dep := range deps {
		if vulns, exists := knownVulnerable[strings.ToLower(dep.Name)]; exists {
			for _, vuln := range vulns {
				if vuln.version == dep.Version {
					findings = append(findings, Finding{
						PackageName:    dep.Name,
						PackageVersion: dep.Version,
						FixedVersion:   vuln.fixed,
						Ecosystem:      dep.Ecosystem,
						ManifestFile:   dep.File,
						Severity:       vuln.severity,
						CVE:            vuln.cve,
						CVSS:           vuln.cvss,
						Description:    vuln.desc,
						Advisory:       fmt.Sprintf("https://osv.dev/vulnerability/%s", vuln.cve),
						OWASP:          config.OWASP_A03_SoftwareSupplyChainFailures,
						Direct:         dep.Direct,
						DependencyPath: dep.Path,
					})
				}
			}
		}
	}

	return findings
}

// stripVersionPrefix removes the leading npm/composer version range
// operator (^, ~, >=, <=, >, <, =) from a version string. Unlike
// strings.TrimLeft, it only strips at most one operator at the start —
// strings.TrimLeft("^>=1.0", "^~>=<") would collapse three operators
// into "1.0" and silently mis-parse a dependency like "^>=1.0".
func stripVersionPrefix(v string) string {
	v = strings.TrimSpace(v)
	for _, op := range []string{">=", "<=", "==", "!=", "~>", "^", "~", ">", "<", "="} {
		if strings.HasPrefix(v, op) {
			return strings.TrimSpace(strings.TrimPrefix(v, op))
		}
	}
	return v
}

// maxManifestSize caps the size of any manifest file we will parse.
// Rationale: the JSON/YAML parsers load the full file into memory before
// validating structure. A crafted or accidentally oversized manifest
// (e.g. 2 GiB package.json) would OOM the scanner mid-run in CI. 10 MiB
// is three orders of magnitude above any legitimate manifest we have
// seen in the wild.
const maxManifestSize = 10 * 1024 * 1024

// readManifestFile reads a manifest with a hard size cap and returns a
// clear error if the file exceeds it. Use this instead of os.ReadFile
// for any manifest that will be fed into json.Unmarshal / yaml.Unmarshal.
func readManifestFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxManifestSize {
		return nil, fmt.Errorf("manifest %s exceeds %d bytes (got %d) — refusing to parse", path, maxManifestSize, info.Size())
	}
	return os.ReadFile(path)
}

// ============= PARSERS =============

// PackageJSONParser parses Node.js package.json files
type PackageJSONParser struct{}

func (p *PackageJSONParser) Name() string    { return "npm/yarn" }
func (p *PackageJSONParser) Files() []string { return []string{"package.json"} }
func (p *PackageJSONParser) Parse(path string) ([]Dependency, error) {
	data, err := readManifestFile(path)
	if err != nil {
		return nil, err
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	var deps []Dependency
	addDeps := func(m map[string]string) {
		for name, version := range m {
			deps = append(deps, Dependency{
				Name:      name,
				Version:   stripVersionPrefix(version),
				Ecosystem: "npm",
				File:      path,
			})
		}
	}
	addDeps(pkg.Dependencies)
	addDeps(pkg.DevDependencies)
	return deps, nil
}

// RequirementsTXTParser parses Python requirements.txt files
type RequirementsTXTParser struct{}

func (p *RequirementsTXTParser) Name() string { return "pip" }
func (p *RequirementsTXTParser) Files() []string {
	return []string{"requirements.txt", "requirements-dev.txt"}
}
func (p *RequirementsTXTParser) Parse(path string) ([]Dependency, error) {
	data, err := readManifestFile(path)
	if err != nil {
		return nil, err
	}

	var deps []Dependency
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		// Drop the environment marker and any trailing comment before reading
		// the version. pip accepts `pkg==1.0 ; python_version < "3.12"  # why`,
		// and neither suffix belongs to the version — carried along, they turn
		// the version into prose that matches no advisory.
		if idx := strings.Index(line, ";"); idx != -1 {
			line = line[:idx]
		}
		if idx := strings.Index(line, "#"); idx != -1 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Handle: package==1.0.0, package>=1.0.0, package~=1.0.0
		for _, sep := range []string{"==", ">=", "<=", "~=", "!=", ">"} {
			if idx := strings.Index(line, sep); idx != -1 {
				name := strings.TrimSpace(line[:idx])
				version := strings.TrimSpace(line[idx+len(sep):])
				// Remove any extra specifiers
				if commaIdx := strings.Index(version, ","); commaIdx != -1 {
					version = version[:commaIdx]
				}
				deps = append(deps, Dependency{
					Name: name, Version: version,
					Ecosystem: "pypi", File: path,
				})
				break
			}
		}
	}
	return deps, nil
}

// GemfileParser parses Ruby Gemfile.lock files
type GemfileParser struct{}

func (p *GemfileParser) Name() string    { return "gem" }
func (p *GemfileParser) Files() []string { return []string{"Gemfile.lock"} }
func (p *GemfileParser) Parse(path string) ([]Dependency, error) {
	data, err := readManifestFile(path)
	if err != nil {
		return nil, err
	}

	var deps []Dependency
	inSpecs := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Section headings (GEM, GIT, PLATFORMS, DEPENDENCIES, BUNDLED WITH)
		// are unindented, and any of them ends the preceding specs listing.
		// Only the specs listing holds resolved versions: DEPENDENCIES repeats
		// the same gems with range constraints such as "rails (~> 7.1.0)".
		if !strings.HasPrefix(line, " ") {
			inSpecs = false
			continue
		}
		if trimmed == "specs:" {
			inSpecs = true
			continue
		}
		if !inSpecs {
			continue
		}

		// Resolved gems sit at exactly four spaces of indentation. Anything
		// deeper is that gem's own requirement on another gem — "actionpack
		// (= 7.1.0)" — which carries an operator, not a resolved version.
		if indent := len(line) - len(strings.TrimLeft(line, " ")); indent != 4 {
			continue
		}

		name, version, ok := parseGemSpec(trimmed)
		if !ok {
			continue
		}
		deps = append(deps, Dependency{
			Name: name, Version: version,
			Ecosystem: "rubygems", File: path,
		})
	}
	return deps, nil
}

// parseGemSpec splits a Gemfile.lock specs entry, "rack (2.2.8)", into its
// name and resolved version. It reports false for anything that does not have
// that exact shape.
func parseGemSpec(line string) (name, version string, ok bool) {
	open := strings.Index(line, " (")
	if open == -1 || !strings.HasSuffix(line, ")") {
		return "", "", false
	}
	name = strings.TrimSpace(line[:open])
	version = strings.TrimSpace(line[open+2 : len(line)-1])
	if name == "" || version == "" {
		return "", "", false
	}
	return name, version, true
}

// GoModParser parses Go go.mod files
type GoModParser struct{}

func (p *GoModParser) Name() string    { return "go" }
func (p *GoModParser) Files() []string { return []string{"go.mod"} }
func (p *GoModParser) Parse(path string) ([]Dependency, error) {
	data, err := readManifestFile(path)
	if err != nil {
		return nil, err
	}

	var deps []Dependency
	inRequire := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "require (" {
			inRequire = true
			continue
		}
		if line == ")" {
			inRequire = false
			continue
		}
		if inRequire || strings.HasPrefix(line, "require ") {
			parts := strings.Fields(strings.TrimPrefix(line, "require "))
			if len(parts) >= 2 {
				deps = append(deps, Dependency{
					Name:      parts[0],
					Version:   strings.TrimSuffix(parts[1], " // indirect"),
					Ecosystem: "go",
					File:      path,
				})
			}
		}
	}
	return deps, nil
}

// PomXMLParser parses Java Maven pom.xml files (simplified)
type PomXMLParser struct{}

func (p *PomXMLParser) Name() string    { return "maven" }
func (p *PomXMLParser) Files() []string { return []string{"pom.xml"} }
func (p *PomXMLParser) Parse(path string) ([]Dependency, error) {
	data, err := readManifestFile(path)
	if err != nil {
		return nil, err
	}

	// Simple regex-based extraction for pom.xml (full XML parsing in Phase 2)
	content := string(data)
	var deps []Dependency

	// Find artifactId/version pairs in dependencies section
	lines := strings.Split(content, "\n")
	var artifactID, version string
	for _, line := range lines {
		if strings.Contains(line, "<artifactId>") {
			artifactID = extractXMLTag(line, "artifactId")
		}
		if strings.Contains(line, "<version>") && artifactID != "" {
			version = extractXMLTag(line, "version")
			if artifactID != "" && version != "" && !strings.HasPrefix(version, "${") {
				deps = append(deps, Dependency{
					Name:      artifactID,
					Version:   version,
					Ecosystem: "maven",
					File:      path,
				})
				artifactID = ""
			}
		}
	}
	return deps, nil
}

// ComposerParser parses PHP composer.json files
type ComposerParser struct{}

func (p *ComposerParser) Name() string    { return "composer" }
func (p *ComposerParser) Files() []string { return []string{"composer.json"} }
func (p *ComposerParser) Parse(path string) ([]Dependency, error) {
	data, err := readManifestFile(path)
	if err != nil {
		return nil, err
	}

	var pkg struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	var deps []Dependency
	addDeps := func(m map[string]string) {
		for name, version := range m {
			if name == "php" {
				continue
			}
			deps = append(deps, Dependency{
				Name:      name,
				Version:   stripVersionPrefix(version),
				Ecosystem: "packagist",
				File:      path,
			})
		}
	}
	addDeps(pkg.Require)
	addDeps(pkg.RequireDev)
	return deps, nil
}

// PubspecParser parses Dart/Flutter pubspec.yaml files
type PubspecParser struct{}

func (p *PubspecParser) Name() string    { return "dart" }
func (p *PubspecParser) Files() []string { return []string{"pubspec.yaml", "pubspec.yml"} }
func (p *PubspecParser) Parse(path string) ([]Dependency, error) {
	data, err := readManifestFile(path)
	if err != nil {
		return nil, err
	}

	var pubspec struct {
		Dependencies    map[string]interface{} `yaml:"dependencies"`
		DevDependencies map[string]interface{} `yaml:"dev_dependencies"`
	}
	if err := yaml.Unmarshal(data, &pubspec); err != nil {
		return nil, err
	}

	var deps []Dependency
	addDeps := func(m map[string]interface{}) {
		for name, ver := range m {
			if name == "flutter" || name == "sdk" {
				continue
			}
			version := ""
			if v, ok := ver.(string); ok {
				version = stripVersionPrefix(v)
			}
			deps = append(deps, Dependency{
				Name:      name,
				Version:   version,
				Ecosystem: "pub",
				File:      path,
			})
		}
	}
	addDeps(pubspec.Dependencies)
	addDeps(pubspec.DevDependencies)
	return deps, nil
}

// extractXMLTag extracts content from a simple XML tag
func extractXMLTag(line, tag string) string {
	open := fmt.Sprintf("<%s>", tag)
	close := fmt.Sprintf("</%s>", tag)
	start := strings.Index(line, open)
	end := strings.Index(line, close)
	if start == -1 || end == -1 {
		return ""
	}
	return strings.TrimSpace(line[start+len(open) : end])
}
