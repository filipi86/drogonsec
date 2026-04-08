package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/drogonsec/drogonsec/internal/ai"
	"github.com/drogonsec/drogonsec/internal/analyzer"
	"github.com/drogonsec/drogonsec/internal/config"
	"github.com/drogonsec/drogonsec/internal/reporter"
	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	outputFormat  string
	outputFile    string
	ignorePaths   []string
	enableAI      bool
	aiAPIKey      string
	aiProvider    string
	aiModel       string
	aiEndpoint    string
	enableGitScan bool
	disableSAST   bool
	disableSCA    bool
	disableLeaks  bool
	severity      string
	languages     []string
	maxWorkers    int
	rulesDir      string
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a directory or file for security vulnerabilities",
	Long: `Perform comprehensive security analysis including:
  • SAST  - Static Application Security Testing (source code vulnerabilities)
  • SCA   - Software Composition Analysis (vulnerable dependencies)  
  • Leaks - Secret detection (credentials, API keys, private keys)
  • IaC   - Infrastructure as Code misconfigurations

Examples:
  drogonsec scan .
  drogonsec scan ./myproject --format json --output report.json
  drogonsec scan . --enable-ai --severity HIGH
  drogonsec scan . --git-history --no-sast
`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "output format: text, json, sarif, html")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file path (default: stdout)")
	scanCmd.Flags().StringSliceVar(&ignorePaths, "ignore", []string{}, "paths to ignore (comma-separated)")
	scanCmd.Flags().BoolVar(&enableAI, "enable-ai", false, "(Coming soon) enable AI remediation suggestions (requires AI_API_KEY)")
	scanCmd.Flags().StringVar(&aiAPIKey, "ai-key", "", "(Coming soon) AI provider API key (or set AI_API_KEY env var)")
	scanCmd.Flags().StringVar(&aiProvider, "ai-provider", "anthropic", "(Coming soon) AI provider: anthropic | openai | azure | custom")
	scanCmd.Flags().StringVar(&aiModel, "ai-model", "", "(Coming soon) AI model name override")
	scanCmd.Flags().StringVar(&aiEndpoint, "ai-endpoint", "", "(Coming soon) custom AI API endpoint URL")
	scanCmd.Flags().BoolVar(&enableGitScan, "git-history", false, "scan git history for leaked secrets")
	scanCmd.Flags().BoolVar(&disableSAST, "no-sast", false, "disable SAST engine")
	scanCmd.Flags().BoolVar(&disableSCA, "no-sca", false, "disable SCA engine")
	scanCmd.Flags().BoolVar(&disableLeaks, "no-leaks", false, "disable leak detection")
	scanCmd.Flags().StringVar(&severity, "severity", "LOW", "minimum severity to report: LOW, MEDIUM, HIGH, CRITICAL")
	scanCmd.Flags().StringSliceVar(&languages, "languages", []string{}, "specific languages to scan (default: auto-detect)")
	scanCmd.Flags().IntVar(&maxWorkers, "workers", 4, "number of parallel workers")
	scanCmd.Flags().StringVar(&rulesDir, "rules-dir", "", "path to custom YAML rules directory")

	// Bind with viper for config file support
	viper.BindPFlag("output.format", scanCmd.Flags().Lookup("format"))
	viper.BindPFlag("ai.enabled", scanCmd.Flags().Lookup("enable-ai"))
	viper.BindPFlag("scan.git_history", scanCmd.Flags().Lookup("git-history"))
	viper.BindPFlag("scan.workers", scanCmd.Flags().Lookup("workers"))
	viper.BindPFlag("scan.min_severity", scanCmd.Flags().Lookup("severity"))
}

func runScan(cmd *cobra.Command, args []string) error {
	startTime := time.Now()

	// Determine path to scan
	scanPath := "."
	if len(args) > 0 {
		scanPath = args[0]
	}

	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return fmt.Errorf("path does not exist: %s", absPath)
	}

	// Resolve AI API key: --ai-key flag → AI_API_KEY → ANTHROPIC_API_KEY (fallback)
	apiKey := aiAPIKey
	if apiKey == "" {
		apiKey = os.Getenv("AI_API_KEY")
	}
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY") // silent fallback for backward compat
	}
	if enableAI && apiKey == "" {
		return fmt.Errorf("AI API key required. Use --ai-key flag or set AI_API_KEY env var")
	}

	// Build scan configuration
	cfg := &config.ScanConfig{
		TargetPath:   absPath,
		OutputFormat: outputFormat,
		OutputFile:   outputFile,
		IgnorePaths:  ignorePaths,
		EnableAI:     enableAI,
		AIAPIKey:     apiKey,
		AIProvider:   aiProvider,
		AIModel:      aiModel,
		AIEndpoint:   aiEndpoint,
		GitHistory:   enableGitScan,
		EnableSAST:   !disableSAST,
		EnableSCA:    !disableSCA,
		EnableLeaks:  !disableLeaks,
		MinSeverity:  severity,
		Languages:    languages,
		MaxWorkers:   maxWorkers,
		Verbose:      viper.GetBool("verbose"),
		RulesDir:     rulesDir,
	}

	// Graphical scan header
	PrintScanBanner(
		absPath,
		cfg.EnableSAST, cfg.EnableSCA, cfg.EnableLeaks, cfg.EnableAI,
		cfg.OutputFormat,
		color.New(color.FgMagenta, color.Bold).SprintFunc(),
	)

	// Run analysis
	a := analyzer.New(cfg)
	result, err := a.Run()
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	result.Duration = time.Since(startTime)

	// AI-powered remediation enrichment (runs after scan, avoids import cycle)
	if cfg.EnableAI && apiKey != "" {
		enrichResult(result, cfg)
	}

	// Generate report
	rep, err := reporter.New(outputFormat)
	if err != nil {
		return err
	}

	output := os.Stdout
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("cannot create output file: %w", err)
		}
		defer f.Close()
		output = f
	}

	if err := rep.Write(result, output); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}

	// Exit code based on vulnerabilities found
	if result.HasCritical() || result.HasHigh() {
		if outputFile != "" {
			color.Red("\n⚠  High/Critical vulnerabilities found. Check report: %s\n", outputFile)
		}
		os.Exit(1)
	}

	return nil
}

// enrichResult calls the AI engine to add remediation suggestions to findings.
func enrichResult(result *analyzer.ScanResult, cfg *config.ScanConfig) {
	client := ai.NewFromScanConfig(cfg)

	// Count findings that need enrichment
	var toEnrich int
	for _, f := range result.SASTFindings {
		if f.Severity == config.SeverityCritical || f.Severity == config.SeverityHigh {
			toEnrich++
		}
	}
	maxLeaks := 5
	if len(result.LeakFindings) < maxLeaks {
		maxLeaks = len(result.LeakFindings)
	}
	toEnrich += maxLeaks

	if toEnrich == 0 {
		return
	}

	fmt.Printf("\n  %s Running AI remediation analysis (%d findings)...\n",
		color.CyanString("→"), toEnrich)

	bar := progressbar.NewOptions(toEnrich,
		progressbar.OptionSetDescription("  AI   "),
		progressbar.OptionSetWidth(40),
		progressbar.OptionShowCount(),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "=",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)

	// Enrich SAST findings (critical/high only)
	enriched := client.EnrichWithRemediation(result.SASTFindings)
	for i, f := range enriched {
		result.SASTFindings[i].AIRemediation = f.AIRemediation
		if f.Severity == config.SeverityCritical || f.Severity == config.SeverityHigh {
			bar.Add(1)
		}
	}

	// Enrich top N leak findings
	for i := range result.LeakFindings {
		if i >= 5 {
			break
		}
		suggestion, err := client.GetLeakRemediation(
			result.LeakFindings[i].Type,
			result.LeakFindings[i].File,
		)
		if err == nil {
			result.LeakFindings[i].AIRemediation = suggestion
		}
		bar.Add(1)
	}

	fmt.Printf("\n  %s AI enrichment complete\n", color.GreenString("✓"))
}
