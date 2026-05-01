package reporter

import (
	"encoding/json"
	"fmt"
	htmlpkg "html"
	"io"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/filipi86/drogonsec/internal/analyzer"
	"github.com/filipi86/drogonsec/internal/config"
)

// safeURL returns the input only if it parses as an http/https URL.
// Any other scheme (javascript:, data:, file:, vbscript:, ...) becomes "#"
// so that href/src attributes rendered in HTML reports cannot execute script.
func safeURL(raw string) string {
	if raw == "" {
		return "#"
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "#"
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return u.String()
	default:
		return "#"
	}
}

// Reporter defines the interface for report generation
type Reporter interface {
	Write(result *analyzer.ScanResult, w io.Writer) error
}

// New creates a reporter for the given format
func New(format string) (Reporter, error) {
	switch strings.ToLower(format) {
	case "text", "":
		return &TextReporter{}, nil
	case "json":
		return &JSONReporter{}, nil
	case "sarif":
		return &SARIFReporter{}, nil
	case "html":
		return &HTMLReporter{}, nil
	default:
		return nil, fmt.Errorf("unknown format: %s (use: text, json, sarif, html)", format)
	}
}

// ============= TEXT REPORTER =============

type TextReporter struct{}

// sanitizeAIResponse cleans raw AI output before formatting, removing
// garbage tokens from local models, filler preamble, and excessive whitespace.
func sanitizeAIResponse(text string) string {
	// 1. Remove known garbage tokens from local models
	garbage := []string{
		"｜begin▁of▁sentence｜",
		"｜end▁of▁sentence｜",
		"<|begin_of_sentence|>",
		"<|end_of_sentence|>",
		"<|im_start|>",
		"<|im_end|>",
		"<s>", "</s>",
	}
	for _, g := range garbage {
		text = strings.ReplaceAll(text, g, "")
	}

	// 2. Remove filler preamble lines (common AI patterns)
	fillerPrefixes := []string{
		"Sure,", "Sure!", "Of course,", "Of course!",
		"Certainly,", "Certainly!", "Here are", "Here is",
		"I'd be happy to", "I'll provide", "Let me",
		"Below are", "The following",
	}
	lines := strings.Split(text, "\n")
	if len(lines) > 0 {
		firstTrimmed := strings.TrimSpace(lines[0])
		for _, prefix := range fillerPrefixes {
			if strings.HasPrefix(firstTrimmed, prefix) {
				lines = lines[1:] // remove first line
				break
			}
		}
	}
	text = strings.Join(lines, "\n")

	// 3. Normalize excessive blank lines (3+ -> 2)
	for strings.Contains(text, "\n\n\n") {
		text = strings.ReplaceAll(text, "\n\n\n", "\n\n")
	}

	// 4. Strip trailing whitespace from each line
	lines = strings.Split(text, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " \t")
	}
	text = strings.Join(lines, "\n")

	// 5. Truncate at ~3000 chars to keep output manageable
	if len(text) > 3000 {
		text = text[:3000]
		// Find last complete line
		if idx := strings.LastIndex(text, "\n"); idx > 2500 {
			text = text[:idx]
		}
		text += "\n\n[... output truncated]"
	}

	return strings.TrimSpace(text)
}

// applyInlineStyles converts **bold** to yellow-bold and `code` to cyan.
// Must be called AFTER wrapLine so ANSI escape codes don't break width math.
func applyInlineStyles(text string, boldFn, codeFn func(a ...interface{}) string) string {
	// Bold: **text** → yellow bold
	for strings.Contains(text, "**") {
		start := strings.Index(text, "**")
		end := strings.Index(text[start+2:], "**")
		if end < 0 {
			break
		}
		boldText := text[start+2 : start+2+end]
		text = text[:start] + boldFn(boldText) + text[start+2+end+2:]
	}
	// Inline code: `code` → cyan
	for strings.Contains(text, "`") {
		start := strings.Index(text, "`")
		end := strings.Index(text[start+1:], "`")
		if end < 0 {
			break
		}
		codeText := text[start+1 : start+1+end]
		text = text[:start] + codeFn(codeText) + text[start+1+end+1:]
	}
	return text
}

// formatAIRemediation converts raw markdown AI remediation text into a
// nicely formatted, indented, terminal-friendly block with box-drawing
// characters and ANSI colors.
func formatAIRemediation(text string) string {
	if text == "" {
		return ""
	}

	text = sanitizeAIResponse(text)
	if text == "" {
		return ""
	}

	headerStyle := color.New(color.FgMagenta, color.Bold).SprintFunc()
	codeStyle := color.New(color.FgCyan).SprintFunc()
	dimStyle := color.New(color.Faint).SprintFunc()
	boldStyle := color.New(color.FgYellow, color.Bold).SprintFunc()

	const maxWidth = 80
	const indent = "  "
	bar := dimStyle("│")

	lines := strings.Split(text, "\n")

	// addWrapped wraps raw text, then applies inline styles to each line,
	// and appends them with the box bar prefix.
	var processed []string
	addWrapped := func(rawText string) {
		for _, wl := range wrapLine(rawText, maxWidth-8) {
			styled := applyInlineStyles(wl, boldStyle, codeStyle)
			processed = append(processed, indent+bar+"  "+styled)
		}
	}

	inCodeBlock := false
	consecutiveBlanks := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Toggle code block state on fences
		if strings.HasPrefix(trimmed, "```") {
			inCodeBlock = !inCodeBlock
			continue // skip the fence lines themselves
		}

		// Handle blank lines — max 1 consecutive
		if trimmed == "" {
			consecutiveBlanks++
			if consecutiveBlanks <= 1 {
				processed = append(processed, indent+bar)
			}
			continue
		}
		consecutiveBlanks = 0

		if inCodeBlock {
			// Code lines: dim gutter + cyan text
			gutter := dimStyle("┊")
			processed = append(processed, indent+bar+"  "+gutter+"  "+codeStyle(trimmed))
			continue
		}

		// Markdown headers -> bold magenta labels
		if strings.HasPrefix(trimmed, "### ") {
			title := strings.TrimPrefix(trimmed, "### ")
			processed = append(processed, indent+bar)
			processed = append(processed, indent+bar+"  "+headerStyle(title))
			continue
		}
		if strings.HasPrefix(trimmed, "## ") {
			title := strings.TrimPrefix(trimmed, "## ")
			processed = append(processed, indent+bar)
			processed = append(processed, indent+bar+"  "+headerStyle(title))
			continue
		}
		if strings.HasPrefix(trimmed, "# ") {
			title := strings.TrimPrefix(trimmed, "# ")
			processed = append(processed, indent+bar)
			processed = append(processed, indent+bar+"  "+headerStyle(title))
			continue
		}

		// Sub-bullets (indented): use hollow bullet
		if strings.HasPrefix(line, "   -") || strings.HasPrefix(line, "   *") ||
			strings.HasPrefix(line, "  -") || strings.HasPrefix(line, "  *") {
			bullet := "  ◦ " + strings.TrimSpace(trimmed[1:])
			addWrapped(bullet)
			continue
		}

		// Bullet points: convert markdown bullets to bullet character
		if strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* ") {
			bullet := "• " + trimmed[2:]
			addWrapped(bullet)
			continue
		}

		// Numbered lists: "1. text", "1) text", "10. text", "1.) text"
		isNumbered := false
		if len(trimmed) >= 2 {
			i := 0
			for i < len(trimmed) && trimmed[i] >= '0' && trimmed[i] <= '9' {
				i++
			}
			if i > 0 && i < len(trimmed) {
				rest := trimmed[i:]
				if strings.HasPrefix(rest, ". ") || strings.HasPrefix(rest, ") ") ||
					strings.HasPrefix(rest, ".) ") {
					isNumbered = true
				}
			}
		}
		if isNumbered {
			addWrapped(trimmed)
			continue
		}

		// Regular text: word-wrap + inline styles
		addWrapped(trimmed)
	}

	// Build the final block with box-drawing frame
	topLabel := color.New(color.Bold).Sprintf("🤖 AI Remediation")
	topLine := indent + dimStyle("┌─ ") + topLabel + " " + dimStyle(strings.Repeat("─", 45))
	bottomLine := indent + dimStyle("└"+strings.Repeat("─", 58))

	var out []string
	out = append(out, "")
	out = append(out, topLine)
	out = append(out, indent+bar)
	out = append(out, processed...)
	out = append(out, indent+bar)
	out = append(out, bottomLine)

	return strings.Join(out, "\n")
}

// wrapLine splits a string into multiple lines, each at most maxWidth
// characters, breaking at word boundaries when possible.
func wrapLine(s string, maxWidth int) []string {
	if len(s) <= maxWidth {
		return []string{s}
	}

	var result []string
	for len(s) > maxWidth {
		// Find last space before maxWidth
		idx := strings.LastIndex(s[:maxWidth], " ")
		if idx <= 0 {
			idx = maxWidth
		}
		result = append(result, s[:idx])
		s = strings.TrimSpace(s[idx:])
	}
	if s != "" {
		result = append(result, s)
	}
	return result
}

func (r *TextReporter) Write(result *analyzer.ScanResult, w io.Writer) error {
	bold := color.New(color.Bold).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	blue := color.New(color.FgBlue).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()

	severityColor := func(s config.Severity) string {
		switch s {
		case config.SeverityCritical:
			return color.New(color.FgRed, color.Bold).Sprint(s)
		case config.SeverityHigh:
			return red(string(s))
		case config.SeverityMedium:
			return yellow(string(s))
		case config.SeverityLow:
			return blue(string(s))
		default:
			return string(s)
		}
	}

	// SAST Findings
	if len(result.SASTFindings) > 0 {
		fmt.Fprintf(w, "\n%s\n", bold("═══ SAST FINDINGS ═══════════════════════════════════════"))
		for i, f := range result.SASTFindings {
			fmt.Fprintf(w, "\n  %s [%s] %s\n", cyan(fmt.Sprintf("#%d", i+1)), severityColor(f.Severity), bold(f.Title))
			fmt.Fprintf(w, "  File     : %s:%d\n", f.File, f.Line)
			fmt.Fprintf(w, "  Rule     : %s\n", f.RuleID)
			fmt.Fprintf(w, "  OWASP    : %s\n", f.OWASP)
			fmt.Fprintf(w, "  CWE      : %s  CVSS: %.1f\n", f.CWE, f.CVSS)
			fmt.Fprintf(w, "  Desc     : %s\n", f.Description)
			if f.Code != "" {
				fmt.Fprintf(w, "  Code     :\n")
				for _, line := range strings.Split(f.Code, "\n") {
					fmt.Fprintf(w, "             %s\n", line)
				}
			}
			fmt.Fprintf(w, "  Fix      : %s\n", green(f.Remediation))
			if len(f.References) > 0 {
				fmt.Fprintf(w, "  Refs     : %s\n", f.References[0])
			}
			if f.AIRemediation != "" {
				fmt.Fprintf(w, "%s\n", formatAIRemediation(f.AIRemediation))
			}
		}
	}

	// Leak Findings
	if len(result.LeakFindings) > 0 {
		fmt.Fprintf(w, "\n%s\n", bold("═══ LEAK FINDINGS ═══════════════════════════════════════"))
		for i, f := range result.LeakFindings {
			fmt.Fprintf(w, "\n  %s [%s] %s\n", cyan(fmt.Sprintf("#%d", i+1)), severityColor(f.Severity), bold(f.Type))
			fmt.Fprintf(w, "  File     : %s:%d\n", f.File, f.Line)
			fmt.Fprintf(w, "  Match    : %s\n", red(f.Match))
			fmt.Fprintf(w, "  Rule     : %s\n", f.RuleID)
			fmt.Fprintf(w, "  Desc     : %s\n", f.Description)
			if f.InGitHistory {
				fmt.Fprintf(w, "  History  : Found in commit %s\n", f.CommitHash)
			}
			if f.AIRemediation != "" {
				fmt.Fprintf(w, "%s\n", formatAIRemediation(f.AIRemediation))
			}
		}
	}

	// SCA Findings
	if len(result.SCAFindings) > 0 {
		fmt.Fprintf(w, "\n%s\n", bold("═══ SCA FINDINGS ════════════════════════════════════════"))
		for i, f := range result.SCAFindings {
			fmt.Fprintf(w, "\n  %s [%s] %s %s\n",
				cyan(fmt.Sprintf("#%d", i+1)),
				severityColor(f.Severity),
				bold(f.PackageName),
				yellow(f.PackageVersion),
			)
			fmt.Fprintf(w, "  CVE      : %s  CVSS: %.1f\n", f.CVE, f.CVSS)
			fmt.Fprintf(w, "  Manifest : %s\n", f.ManifestFile)
			fmt.Fprintf(w, "  Fixed in : %s\n", green(f.FixedVersion))
			fmt.Fprintf(w, "  Desc     : %s\n", f.Description)
			fmt.Fprintf(w, "  Advisory : %s\n", f.Advisory)
		}
	}

	return nil
}

// ============= JSON REPORTER =============

type JSONReporter struct{}

type jsonOutput struct {
	Version      string                 `json:"version"`
	ScanTime     string                 `json:"scan_time"`
	Duration     string                 `json:"duration"`
	Target       string                 `json:"target"`
	Stats        analyzer.ScanStats     `json:"stats"`
	SASTFindings []analyzer.Finding     `json:"sast_findings"`
	SCAFindings  []analyzer.SCAFinding  `json:"sca_findings"`
	LeakFindings []analyzer.LeakFinding `json:"leak_findings"`
}

func (r *JSONReporter) Write(result *analyzer.ScanResult, w io.Writer) error {
	out := jsonOutput{
		Version:      result.Version,
		ScanTime:     result.ScanTime.Format(time.RFC3339),
		Duration:     result.Duration.String(),
		Target:       result.TargetPath,
		Stats:        result.Stats,
		SASTFindings: result.SASTFindings,
		SCAFindings:  result.SCAFindings,
		LeakFindings: result.LeakFindings,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// ============= SARIF REPORTER =============
// SARIF 2.1.0 - Standard format for GitHub, Azure DevOps, GitLab integration

type SARIFReporter struct{}

type sarifOutput struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	ShortDescription sarifMessage           `json:"shortDescription"`
	FullDescription  sarifMessage           `json:"fullDescription"`
	Properties       map[string]interface{} `json:"properties"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

// sarifRelPath returns a path relative to targetPath for use in SARIF URIs.
// Absolute paths in SARIF expose server-side filesystem layout; relative
// paths are required by the SARIF 2.1 spec when originalUriBaseIds is set.
func sarifRelPath(targetPath, filePath string) string {
	rel, err := filepath.Rel(targetPath, filePath)
	if err != nil {
		return filePath
	}
	return filepath.ToSlash(rel)
}

func (r *SARIFReporter) Write(result *analyzer.ScanResult, w io.Writer) error {
	var rules []sarifRule
	var results []sarifResult

	ruleSet := make(map[string]bool)

	// Add SAST findings
	for _, f := range result.SASTFindings {
		if !ruleSet[f.RuleID] {
			rules = append(rules, sarifRule{
				ID:               f.RuleID,
				Name:             strings.ReplaceAll(f.Title, " ", ""),
				ShortDescription: sarifMessage{Text: f.Title},
				FullDescription:  sarifMessage{Text: f.Description},
				Properties: map[string]interface{}{
					"severity": string(f.Severity),
					"owasp":    string(f.OWASP),
					"cwe":      f.CWE,
					"cvss":     f.CVSS,
				},
			})
			ruleSet[f.RuleID] = true
		}

		results = append(results, sarifResult{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: fmt.Sprintf("%s - %s", f.Title, f.Remediation)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: sarifRelPath(result.TargetPath, f.File)},
					Region:           sarifRegion{StartLine: sarifStartLine(f.Line), StartColumn: f.Column},
				},
			}},
		})
	}

	// Add Leak findings
	for _, f := range result.LeakFindings {
		ruleID := f.RuleID
		if !ruleSet[ruleID] {
			rules = append(rules, sarifRule{
				ID:               ruleID,
				Name:             strings.ReplaceAll(f.Type, " ", ""),
				ShortDescription: sarifMessage{Text: f.Type},
				FullDescription:  sarifMessage{Text: f.Description},
				Properties: map[string]interface{}{
					"severity": string(f.Severity),
				},
			})
			ruleSet[ruleID] = true
		}

		results = append(results, sarifResult{
			RuleID:  ruleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: fmt.Sprintf("Secret detected: %s", f.Type)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: sarifRelPath(result.TargetPath, f.File)},
					Region:           sarifRegion{StartLine: sarifStartLine(f.Line)},
				},
			}},
		})
	}

	sarif := sarifOutput{
		Schema:  "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "DrogonSec Security Scanner",
				Version:        result.Version,
				InformationURI: "https://github.com/filipi86/drogonsec",
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarif)
}

func sarifLevel(s config.Severity) string {
	switch s {
	case config.SeverityCritical, config.SeverityHigh:
		return "error"
	case config.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// sarifStartLine clamps a line number to the minimum valid value for SARIF (1).
// The SARIF 2.1 spec requires startLine >= 1; a zero value produced by a
// finding with an unknown position would generate an invalid SARIF document
// that GitHub's Security tab and other consumers reject.
func sarifStartLine(line int) int {
	if line < 1 {
		return 1
	}
	return line
}

// ============= HTML REPORTER =============

type HTMLReporter struct{}

func (r *HTMLReporter) Write(result *analyzer.ScanResult, w io.Writer) error {
	severityBadge := func(s config.Severity) string {
		colors := map[config.Severity]string{
			config.SeverityCritical: "#dc2626",
			config.SeverityHigh:     "#ea580c",
			config.SeverityMedium:   "#ca8a04",
			config.SeverityLow:      "#2563eb",
			config.SeverityInfo:     "#6b7280",
		}
		c := colors[s]
		if c == "" {
			c = "#6b7280"
		}
		return fmt.Sprintf(`<span class="badge" style="background:%s">%s</span>`, c, s)
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DrogonSec Security Report</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; }
  .header { background: linear-gradient(135deg, #1e293b 0%%, #0f172a 100%%); padding: 2rem; border-bottom: 1px solid #334155; }
  .header h1 { font-size: 2rem; color: #38bdf8; margin-bottom: 0.5rem; }
  .header p { color: #94a3b8; }
  .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
  .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin: 2rem 0; }
  .stat-card { background: #1e293b; border: 1px solid #334155; border-radius: 0.5rem; padding: 1.5rem; text-align: center; }
  .stat-card .number { font-size: 2.5rem; font-weight: bold; }
  .stat-card .label { color: #94a3b8; font-size: 0.875rem; margin-top: 0.25rem; }
  .critical { color: #dc2626; } .high { color: #ea580c; } .medium { color: #ca8a04; }
  .low { color: #2563eb; } .info { color: #6b7280; }
  .section { margin: 2rem 0; }
  .section h2 { color: #38bdf8; font-size: 1.25rem; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid #334155; }
  .finding { background: #1e293b; border: 1px solid #334155; border-radius: 0.5rem; padding: 1.5rem; margin-bottom: 1rem; }
  .finding-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem; }
  .finding-title { font-weight: 600; font-size: 1.1rem; }
  .badge { padding: 0.25rem 0.75rem; border-radius: 9999px; color: white; font-size: 0.75rem; font-weight: 600; }
  .finding-meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0.5rem; margin-bottom: 1rem; }
  .meta-item { font-size: 0.875rem; color: #94a3b8; }
  .meta-item strong { color: #e2e8f0; }
  .code-block { background: #0f172a; border: 1px solid #334155; border-radius: 0.375rem; padding: 1rem; font-family: 'Courier New', monospace; font-size: 0.8rem; overflow-x: auto; white-space: pre; margin: 0.75rem 0; }
  .remediation { background: #064e3b; border: 1px solid #065f46; border-radius: 0.375rem; padding: 1rem; margin-top: 0.75rem; font-size: 0.875rem; }
  .remediation::before { content: "✓ Fix: "; font-weight: bold; color: #34d399; }
  .ai-remediation { background: #1e1b4b; border: 1px solid #4338ca; border-radius: 0.375rem; padding: 1rem; margin-top: 0.75rem; font-size: 0.875rem; }
  .ai-remediation strong { color: #818cf8; }
  .ai-remediation p { margin: 0.5rem 0 0; color: #c7d2fe; white-space: pre-wrap; }
</style>
</head>
<body>
<div class="header">
  <div style="max-width:1200px;margin:0 auto">
    <h1>🛡️ DrogonSec Security Report</h1>
    <p>Target: %s | Scanned: %s | Duration: %s</p>
  </div>
</div>
<div class="container">
  <div class="stats-grid">
    <div class="stat-card"><div class="number">%d</div><div class="label">Total Findings</div></div>
    <div class="stat-card"><div class="number critical">%d</div><div class="label">Critical</div></div>
    <div class="stat-card"><div class="number high">%d</div><div class="label">High</div></div>
    <div class="stat-card"><div class="number medium">%d</div><div class="label">Medium</div></div>
    <div class="stat-card"><div class="number low">%d</div><div class="label">Low</div></div>
    <div class="stat-card"><div class="number">%d</div><div class="label">Files Scanned</div></div>
  </div>`,
		htmlpkg.EscapeString(result.TargetPath),
		result.ScanTime.Format("2006-01-02 15:04:05"),
		result.Duration.Round(time.Millisecond),
		result.Stats.TotalFindings,
		result.Stats.CriticalCount,
		result.Stats.HighCount,
		result.Stats.MediumCount,
		result.Stats.LowCount,
		result.FilesScanned,
	)

	// SAST Findings section
	if len(result.SASTFindings) > 0 {
		html += fmt.Sprintf(`<div class="section"><h2>🔍 SAST Findings (%d)</h2>`, len(result.SASTFindings))
		for _, f := range result.SASTFindings {
			aiSection := ""
			if f.AIRemediation != "" {
				aiSection = fmt.Sprintf(`<div class="ai-remediation"><strong>🤖 AI Remediation:</strong><p>%s</p></div>`, htmlpkg.EscapeString(f.AIRemediation))
			}
			html += fmt.Sprintf(`
<div class="finding">
  <div class="finding-header">%s<span class="finding-title">%s</span></div>
  <div class="finding-meta">
    <div class="meta-item"><strong>File:</strong> %s:%d</div>
    <div class="meta-item"><strong>Rule:</strong> %s</div>
    <div class="meta-item"><strong>OWASP:</strong> %s</div>
    <div class="meta-item"><strong>CWE:</strong> %s | CVSS: %.1f</div>
  </div>
  <p style="color:#94a3b8;font-size:0.875rem">%s</p>
  <div class="remediation">%s</div>
  %s
</div>`, severityBadge(f.Severity), htmlpkg.EscapeString(f.Title), htmlpkg.EscapeString(f.File), f.Line, htmlpkg.EscapeString(f.RuleID), htmlpkg.EscapeString(string(f.OWASP)), htmlpkg.EscapeString(f.CWE), f.CVSS, htmlpkg.EscapeString(f.Description), htmlpkg.EscapeString(f.Remediation), aiSection)
		}
		html += `</div>`
	}

	// Leak Findings section
	if len(result.LeakFindings) > 0 {
		html += fmt.Sprintf(`<div class="section"><h2>🔑 Leak Findings (%d)</h2>`, len(result.LeakFindings))
		for _, f := range result.LeakFindings {
			aiSection := ""
			if f.AIRemediation != "" {
				aiSection = fmt.Sprintf(`<div class="ai-remediation"><strong>🤖 AI Remediation:</strong><p>%s</p></div>`, htmlpkg.EscapeString(f.AIRemediation))
			}
			html += fmt.Sprintf(`
<div class="finding">
  <div class="finding-header">%s<span class="finding-title">%s</span></div>
  <div class="finding-meta">
    <div class="meta-item"><strong>File:</strong> %s:%d</div>
    <div class="meta-item"><strong>Rule:</strong> %s</div>
    <div class="meta-item"><strong>Match:</strong> <code style="color:#f87171">%s</code></div>
  </div>
  <p style="color:#94a3b8;font-size:0.875rem">%s</p>
  %s
</div>`, severityBadge(f.Severity), htmlpkg.EscapeString(f.Type), htmlpkg.EscapeString(f.File), f.Line, htmlpkg.EscapeString(f.RuleID), htmlpkg.EscapeString(f.Match), htmlpkg.EscapeString(f.Description), aiSection)
		}
		html += `</div>`
	}

	// SCA Findings section
	if len(result.SCAFindings) > 0 {
		html += fmt.Sprintf(`<div class="section"><h2>📦 SCA Findings (%d)</h2>`, len(result.SCAFindings))
		for _, f := range result.SCAFindings {
			html += fmt.Sprintf(`
<div class="finding">
  <div class="finding-header">%s<span class="finding-title">%s %s</span></div>
  <div class="finding-meta">
    <div class="meta-item"><strong>CVE:</strong> %s | CVSS: %.1f</div>
    <div class="meta-item"><strong>Manifest:</strong> %s</div>
    <div class="meta-item"><strong>Fixed in:</strong> %s</div>
    <div class="meta-item"><strong>Ecosystem:</strong> %s</div>
  </div>
  <p style="color:#94a3b8;font-size:0.875rem">%s</p>
  <div class="remediation">Upgrade to version %s or higher. See: <a href="%s" rel="noopener noreferrer nofollow" target="_blank" style="color:#38bdf8">%s</a></div>
</div>`, severityBadge(f.Severity), htmlpkg.EscapeString(f.PackageName), htmlpkg.EscapeString(f.PackageVersion), htmlpkg.EscapeString(f.CVE), f.CVSS, htmlpkg.EscapeString(f.ManifestFile), htmlpkg.EscapeString(f.FixedVersion), htmlpkg.EscapeString(f.Ecosystem), htmlpkg.EscapeString(f.Description), htmlpkg.EscapeString(f.FixedVersion), htmlpkg.EscapeString(safeURL(f.Advisory)), htmlpkg.EscapeString(f.CVE))
		}
		html += `</div>`
	}

	html += `</div>
<div style="text-align:center;padding:2rem;color:#475569;font-size:0.875rem">
  Generated by <strong>DrogonSec Security Scanner</strong> | Aligned with OWASP Top 10:2025
</div>
</body></html>`

	_, err := fmt.Fprint(w, html)
	return err
}
