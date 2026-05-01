package engine

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/filipi86/drogonsec/internal/config"
)

// Finding mirrors analyzer.Finding but kept local to avoid import cycle
type Finding struct {
	ID            string
	Type          config.FindingType
	Language      config.Language
	Severity      config.Severity
	Title         string
	Description   string
	File          string
	Line          int
	Column        int
	Code          string
	RuleID        string
	OWASP         config.OWASPCategory
	CWE           string
	CVSS          float64
	References    []string
	Remediation   string
	AIRemediation string
	FalsePositive bool
}

// Rule defines a security detection rule
type Rule struct {
	ID          string
	Language    config.Language
	Title       string
	Description string
	Pattern     *regexp.Regexp
	// AntiPattern, when non-nil and matching the same line, suppresses
	// the finding. Used to avoid false positives when a mitigation marker
	// (e.g., autocomplete="off") is already present on the matched line.
	// Go RE2 has no negative lookahead, so we model it as an explicit
	// second-pass check.
	AntiPattern *regexp.Regexp
	Severity    config.Severity
	OWASP       config.OWASPCategory
	CWE         string
	CVSS        float64
	References  []string
	Remediation string
}

// Engine is the SAST analysis engine
type Engine struct {
	rules []Rule
}

// New creates a new Engine with all built-in rules loaded
func New() *Engine {
	e := &Engine{}
	e.loadAllRules()
	return e
}

// NewWithCustomRules creates a new Engine and additionally loads YAML rules from rulesDir.
// If rulesDir is empty or does not exist, only built-in rules are used.
func NewWithCustomRules(rulesDir string) *Engine {
	e := New()
	if rulesDir != "" {
		if _, err := os.Stat(rulesDir); err == nil {
			n, errs := e.LoadYAMLRules(rulesDir)
			if n > 0 {
				_ = n // caller can check via RuleCount()
			}
			_ = errs // non-fatal: built-in rules still work
		}
	}
	return e
}

// Analyze scans a single file and returns all findings
func (e *Engine) Analyze(filePath string) []Finding {
	ext := strings.ToLower(filepath.Ext(filePath))
	lang, ok := config.FileExtensionMap[ext]
	if !ok {
		return nil
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}

	var findings []Finding
	lines := strings.Split(string(content), "\n")

	for _, rule := range e.rules {
		if rule.Language != lang && rule.Language != config.LangGeneric {
			continue
		}

		scanner := bufio.NewScanner(strings.NewReader(string(content)))
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()

			if rule.Pattern.MatchString(line) {
				if rule.AntiPattern != nil && rule.AntiPattern.MatchString(line) {
					continue
				}
				col := findColumn(line, rule.Pattern)
				snippet := buildSnippet(lines, lineNum, 3)

				findings = append(findings, Finding{
					ID:          fmt.Sprintf("%s-%s-%d", rule.ID, filepath.Base(filePath), lineNum),
					Type:        config.FindingTypeSAST,
					Language:    lang,
					Severity:    rule.Severity,
					Title:       rule.Title,
					Description: rule.Description,
					File:        filePath,
					Line:        lineNum,
					Column:      col,
					Code:        snippet,
					RuleID:      rule.ID,
					OWASP:       rule.OWASP,
					CWE:         rule.CWE,
					CVSS:        rule.CVSS,
					References:  rule.References,
					Remediation: rule.Remediation,
				})
			}
		}
	}

	return findings
}

// loadAllRules registers all built-in detection rules
func (e *Engine) loadAllRules() {
	e.rules = append(e.rules, pythonRules()...)
	e.rules = append(e.rules, javaRules()...)
	e.rules = append(e.rules, javascriptRules()...)
	e.rules = append(e.rules, golangRules()...)
	e.rules = append(e.rules, phpRules()...)
	e.rules = append(e.rules, kotlinRules()...)
	e.rules = append(e.rules, csharpRules()...)
	e.rules = append(e.rules, shellRules()...)
	e.rules = append(e.rules, terraformRules()...)
	e.rules = append(e.rules, kubernetesRules()...)
	e.rules = append(e.rules, htmlRules()...)
	e.rules = append(e.rules, genericRules()...)
}

// RuleCount returns total number of loaded rules
func (e *Engine) RuleCount() int {
	return len(e.rules)
}

// helper: find column of first match in line
func findColumn(line string, re *regexp.Regexp) int {
	loc := re.FindStringIndex(line)
	if loc == nil {
		return 0
	}
	return loc[0] + 1
}

// helper: build a code snippet around a line
func buildSnippet(lines []string, lineNum, context int) string {
	start := lineNum - context - 1
	end := lineNum + context
	if start < 0 {
		start = 0
	}
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "\n")
}

// mustCompile compiles regex or returns a never-matching pattern on error.
// The fallback uses [^\s\S] because `$^` still matches empty strings (blank
// lines), which caused false positives for rules with invalid regex.
// Invalid patterns are logged to stderr so rule authors are not left
// wondering why a custom rule silently produces zero findings.
func mustCompile(pattern string) *regexp.Regexp {
	re, err := regexp.Compile(pattern)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ⚠  invalid rule pattern (rule disabled): %v\n", err)
		return regexp.MustCompile(`[^\s\S]`) // truly never matches
	}
	return re
}
