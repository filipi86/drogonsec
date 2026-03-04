package sca

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/drogonsec/drogonsec/internal/config"
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
}

// Dependency represents a parsed dependency
type Dependency struct {
	Name      string
	Version   string
	Ecosystem string
	File      string
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

	if len(deps) == 0 {
		return nil, nil
	}

	fmt.Printf("  Found %d dependencies across %d manifest files\n", len(deps), e.countUniqueFiles(deps))

	// Query OSV API for real vulnerability data, fall back to demo DB on error
	osv := newOSVClient()
	findings, err := osv.QueryBatch(deps)
	if err != nil {
		fmt.Printf("  OSV API unavailable (%v), falling back to local database\n", err)
		findings = e.checkKnownVulnerabilities(deps)
	}

	return findings, nil
}

// collectDependencies finds and parses all manifest files
func (e *Engine) collectDependencies() ([]Dependency, error) {
	var allDeps []Dependency

	for _, parser := range e.parsers {
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

				if filepath.Base(path) == manifestName {
					deps, parseErr := parser.Parse(path)
					if parseErr == nil {
						allDeps = append(allDeps, deps...)
					}
				}
				return nil
			})
			if err != nil {
				continue
			}
		}
	}

	return allDeps, nil
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
					})
				}
			}
		}
	}

	return findings
}

// ============= PARSERS =============

// PackageJSONParser parses Node.js package.json files
type PackageJSONParser struct{}

func (p *PackageJSONParser) Name() string    { return "npm/yarn" }
func (p *PackageJSONParser) Files() []string { return []string{"package.json"} }
func (p *PackageJSONParser) Parse(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
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
				Version:   strings.TrimLeft(version, "^~>=<"),
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
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var deps []Dependency
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
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
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var deps []Dependency
	inSpecs := false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "GEM" {
			inSpecs = true
		}
		if inSpecs && strings.Contains(line, "(") && strings.Contains(line, ")") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				name := strings.TrimSpace(parts[0])
				version := strings.Trim(parts[1], "()")
				deps = append(deps, Dependency{
					Name: name, Version: version,
					Ecosystem: "rubygems", File: path,
				})
			}
		}
	}
	return deps, nil
}

// GoModParser parses Go go.mod files
type GoModParser struct{}

func (p *GoModParser) Name() string    { return "go" }
func (p *GoModParser) Files() []string { return []string{"go.mod"} }
func (p *GoModParser) Parse(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
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
	data, err := os.ReadFile(path)
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
	data, err := os.ReadFile(path)
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
				Version:   strings.TrimLeft(version, "^~>=<"),
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
	data, err := os.ReadFile(path)
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
				version = strings.TrimLeft(v, "^~>=<")
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
