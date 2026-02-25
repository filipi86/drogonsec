package engine

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/drogonsec/drogonsec/internal/config"
	"gopkg.in/yaml.v3"
)

// YAMLRule represents a community-contributed rule in YAML format
type YAMLRule struct {
	ID          string   `yaml:"id"`
	Language    string   `yaml:"language"`
	Title       string   `yaml:"title"`
	Description string   `yaml:"description"`
	Pattern     string   `yaml:"pattern"`
	Severity    string   `yaml:"severity"`
	OWASP       string   `yaml:"owasp"`
	CWE         string   `yaml:"cwe"`
	CVSS        float64  `yaml:"cvss"`
	References  []string `yaml:"references"`
	Remediation string   `yaml:"remediation"`
}

// YAMLRuleFile is the top-level structure of a rule file
type YAMLRuleFile struct {
	Rules []YAMLRule `yaml:"rules"`
}

// LoadYAMLRules scans a directory tree for *.yaml/*.yml rule files and loads them
// into the engine. Returns the number of rules loaded and any non-fatal errors.
func (e *Engine) LoadYAMLRules(rulesDir string) (int, []error) {
	var errs []error
	loaded := 0

	err := filepath.WalkDir(rulesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		n, fileErrs := e.loadYAMLFile(path)
		loaded += n
		errs = append(errs, fileErrs...)
		return nil
	})

	if err != nil {
		errs = append(errs, fmt.Errorf("walk %s: %w", rulesDir, err))
	}

	return loaded, errs
}

// loadYAMLFile parses a single YAML rule file and registers its rules
func (e *Engine) loadYAMLFile(path string) (int, []error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, []error{fmt.Errorf("read %s: %w", path, err)}
	}

	var ruleFile YAMLRuleFile
	if err := yaml.Unmarshal(data, &ruleFile); err != nil {
		return 0, []error{fmt.Errorf("parse %s: %w", path, err)}
	}

	var errs []error
	loaded := 0

	for _, yr := range ruleFile.Rules {
		rule, err := yamlRuleToRule(yr)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s rule %s: %w", path, yr.ID, err))
			continue
		}
		e.rules = append(e.rules, rule)
		loaded++
	}

	return loaded, errs
}

// yamlRuleToRule converts a parsed YAMLRule to the internal Rule type
func yamlRuleToRule(yr YAMLRule) (Rule, error) {
	if yr.ID == "" {
		return Rule{}, fmt.Errorf("missing id")
	}
	if yr.Pattern == "" {
		return Rule{}, fmt.Errorf("missing pattern")
	}

	re, err := regexp.Compile(yr.Pattern)
	if err != nil {
		return Rule{}, fmt.Errorf("invalid pattern %q: %w", yr.Pattern, err)
	}

	lang := parseLanguage(yr.Language)
	severity := parseSeverity(yr.Severity)
	owasp := parseOWASP(yr.OWASP)

	return Rule{
		ID:          yr.ID,
		Language:    lang,
		Title:       yr.Title,
		Description: yr.Description,
		Pattern:     re,
		Severity:    severity,
		OWASP:       owasp,
		CWE:         yr.CWE,
		CVSS:        yr.CVSS,
		References:  yr.References,
		Remediation: yr.Remediation,
	}, nil
}

// parseLanguage maps a YAML language string to config.Language
func parseLanguage(s string) config.Language {
	switch strings.ToLower(s) {
	case "java":
		return config.LangJava
	case "kotlin":
		return config.LangKotlin
	case "javascript", "js":
		return config.LangJavaScript
	case "typescript", "ts":
		return config.LangTypeScript
	case "python", "py":
		return config.LangPython
	case "ruby", "rb":
		return config.LangRuby
	case "go", "golang":
		return config.LangGo
	case "csharp", "c#", "cs":
		return config.LangCSharp
	case "php":
		return config.LangPHP
	case "swift":
		return config.LangSwift
	case "dart":
		return config.LangDart
	case "elixir", "ex":
		return config.LangElixir
	case "erlang", "erl":
		return config.LangErlang
	case "shell", "bash", "sh":
		return config.LangShell
	case "c", "cpp", "c++":
		return config.LangC
	case "html":
		return config.LangHTML
	case "terraform", "tf", "hcl":
		return config.LangTerraform
	case "kubernetes", "k8s":
		return config.LangKubernetes
	case "nginx":
		return config.LangNginx
	default:
		return config.LangGeneric
	}
}

// parseSeverity maps a YAML severity string to config.Severity
func parseSeverity(s string) config.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return config.SeverityCritical
	case "HIGH":
		return config.SeverityHigh
	case "MEDIUM":
		return config.SeverityMedium
	case "LOW":
		return config.SeverityLow
	default:
		return config.SeverityMedium
	}
}

// parseOWASP maps an OWASP ID string to config.OWASPCategory
func parseOWASP(s string) config.OWASPCategory {
	switch {
	case strings.Contains(s, "A01"):
		return config.OWASP_A01_BrokenAccessControl
	case strings.Contains(s, "A02"):
		return config.OWASP_A02_SecurityMisconfiguration
	case strings.Contains(s, "A03"):
		return config.OWASP_A03_SoftwareSupplyChainFailures
	case strings.Contains(s, "A04"):
		return config.OWASP_A04_CryptographicFailures
	case strings.Contains(s, "A05"):
		return config.OWASP_A05_Injection
	case strings.Contains(s, "A06"):
		return config.OWASP_A06_InsecureDesign
	case strings.Contains(s, "A07"):
		return config.OWASP_A07_AuthenticationFailures
	case strings.Contains(s, "A08"):
		return config.OWASP_A08_SoftwareDataIntegrityFailures
	case strings.Contains(s, "A09"):
		return config.OWASP_A09_SecurityLoggingAlertingFailures
	case strings.Contains(s, "A10"):
		return config.OWASP_A10_MishandlingExceptionalConditions
	default:
		return config.OWASPCategory(s)
	}
}
