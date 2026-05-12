package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/filipi86/drogonsec/internal/ai"
	"github.com/filipi86/drogonsec/internal/analyzer"
	"github.com/filipi86/drogonsec/internal/config"
	"github.com/filipi86/drogonsec/internal/reporter"
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
	aiTimeout     int
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
	scanCmd.Flags().BoolVar(&enableAI, "enable-ai", false, "enable AI-powered remediation suggestions")
	scanCmd.Flags().StringVar(&aiAPIKey, "ai-key", "", "AI provider API key (or set AI_API_KEY env var; not needed for ollama)")
	scanCmd.Flags().StringVar(&aiProvider, "ai-provider", "anthropic", "AI provider: ollama | anthropic | openai | azure | custom")
	scanCmd.Flags().StringVar(&aiModel, "ai-model", "", "AI model name override (default: deepseek-coder for ollama)")
	scanCmd.Flags().StringVar(&aiEndpoint, "ai-endpoint", "", "custom AI API endpoint URL")
	scanCmd.Flags().IntVar(&aiTimeout, "ai-timeout", 0, "AI request timeout in seconds (default: 30 cloud, 120 ollama)")
	scanCmd.Flags().BoolVar(&enableGitScan, "git-history", false, "scan git history for leaked secrets")
	scanCmd.Flags().BoolVar(&disableSAST, "no-sast", false, "disable SAST engine")
	scanCmd.Flags().BoolVar(&disableSCA, "no-sca", false, "disable SCA engine")
	scanCmd.Flags().BoolVar(&disableLeaks, "no-leaks", false, "disable leak detection")
	scanCmd.Flags().StringVar(&severity, "severity", "LOW", "minimum severity to report: LOW, MEDIUM, HIGH, CRITICAL")
	scanCmd.Flags().StringSliceVar(&languages, "languages", []string{}, "specific languages to scan (default: auto-detect)")
	scanCmd.Flags().IntVar(&maxWorkers, "workers", 4, "number of parallel workers")
	scanCmd.Flags().StringVar(&rulesDir, "rules-dir", "", "path to custom YAML rules directory")

	// Tab completion: enum values and path types for every flag.
	// Rationale: Cobra's default completer attempts filename completion on
	// every string flag, which is noisy and — for --ai-key — would surface
	// cached shell suggestions for a secret. Registering explicit functions
	// gives users useful suggestions without leaking anything.
	_ = scanCmd.RegisterFlagCompletionFunc("format", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return completionFormat, cobra.ShellCompDirectiveNoFileComp
	})
	_ = scanCmd.RegisterFlagCompletionFunc("severity", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return completionSeverity, cobra.ShellCompDirectiveNoFileComp
	})
	_ = scanCmd.RegisterFlagCompletionFunc("ai-provider", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return completionAIProvider, cobra.ShellCompDirectiveNoFileComp
	})
	_ = scanCmd.RegisterFlagCompletionFunc("ai-model", completeAIModel)
	_ = scanCmd.RegisterFlagCompletionFunc("languages", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return completionLanguages, cobra.ShellCompDirectiveNoFileComp
	})
	// Directory-only flags.
	_ = scanCmd.RegisterFlagCompletionFunc("rules-dir", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveFilterDirs
	})
	_ = scanCmd.RegisterFlagCompletionFunc("ignore", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveFilterDirs
	})
	// Security: never offer filesystem completion for the API key — we
	// don't want `drogonsec scan . --ai-key <TAB>` to enumerate files or
	// pull secrets out of shell history caches.
	_ = scanCmd.RegisterFlagCompletionFunc("ai-key", cobra.NoFileCompletions)
	_ = scanCmd.RegisterFlagCompletionFunc("ai-endpoint", cobra.NoFileCompletions)
	_ = scanCmd.RegisterFlagCompletionFunc("ai-timeout", cobra.NoFileCompletions)
	_ = scanCmd.RegisterFlagCompletionFunc("workers", cobra.NoFileCompletions)
	// Positional argument: scan path — directories only.
	scanCmd.ValidArgsFunction = func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveFilterDirs
	}

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

	// Auto-detect Ollama when AI enabled but no key provided
	if enableAI && apiKey == "" {
		switch aiProvider {
		case "ollama":
			// Ollama doesn't need an API key — just verify it's running
		case "anthropic":
			// Default provider: try to auto-detect local Ollama
			if detectOllama() {
				aiProvider = "ollama"
				fmt.Printf("  %s Ollama detected locally — using local AI (model: %s)\n",
					color.CyanString("→"), resolveOllamaModel())
			} else {
				return fmt.Errorf("AI API key required. Use --ai-key flag, set AI_API_KEY env var, or install Ollama for free local AI")
			}
		default:
			return fmt.Errorf("AI API key required for provider %q. Use --ai-key flag or set AI_API_KEY env var", aiProvider)
		}
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
		AITimeout:    time.Duration(aiTimeout) * time.Second,
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
	if cfg.EnableAI && (apiKey != "" || cfg.AIProvider == "ollama") {
		enrichResult(result, cfg)
	}

	// Generate report
	rep, err := reporter.New(outputFormat)
	if err != nil {
		return err
	}

	output := os.Stdout
	if outputFile != "" {
		// Create the report with user-only perms (0o600). Reports embed
		// vulnerable code snippets, rule matches, and in some cases AI
		// remediation text; on shared or CI filesystems they should not
		// be world-readable by default.
		f, err := os.OpenFile(outputFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
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
			// Printf-style formatting requires the color object's Printf method —
			// the package-level color.Red is a PrintFunc (Fprint-based) and does
			// not interpolate format verbs, so %s would be printed literally.
			color.New(color.FgRed).Printf("\n⚠  High/Critical vulnerabilities found. Check report: %s\n", outputFile)
		}
		os.Exit(1)
	}

	return nil
}

// enrichResult calls the AI engine to add remediation suggestions to findings.
func enrichResult(result *analyzer.ScanResult, cfg *config.ScanConfig) {
	client := ai.NewFromScanConfig(cfg)

	// Verify AI backend is reachable before processing
	if err := client.CheckHealth(); err != nil {
		fmt.Printf("  %s AI unavailable: %s\n", color.RedString("✗"), err)
		return
	}

	// Collect work items
	type workItem struct {
		kind  string // "sast" or "leak"
		index int
		label string
	}
	var items []workItem

	for i, f := range result.SASTFindings {
		if f.Severity == config.SeverityCritical || f.Severity == config.SeverityHigh {
			items = append(items, workItem{"sast", i, f.Title})
		}
	}
	maxLeaks := 5
	if len(result.LeakFindings) < maxLeaks {
		maxLeaks = len(result.LeakFindings)
	}
	for i := 0; i < maxLeaks; i++ {
		items = append(items, workItem{"leak", i, result.LeakFindings[i].Type})
	}

	total := len(items)
	if total == 0 {
		return
	}

	dim := color.New(color.Faint).SprintFunc()

	fmt.Printf("\n  %s Running AI remediation (%d findings)...\n\n",
		color.CyanString("\U0001F916"), total)

	totalStart := time.Now()
	var errCount int
	var lastErr error

	for idx, item := range items {
		// Truncate label to 40 chars
		label := item.label
		if len(label) > 40 {
			label = label[:37] + "..."
		}

		// Print progress prefix (no newline yet)
		prefix := fmt.Sprintf("  %s [%d/%d] %s", color.CyanString("\u2192"), idx+1, total, label)

		// Pad with dots to column 58
		dots := ""
		padLen := 58 - len(fmt.Sprintf("  \u2192 [%d/%d] %s", idx+1, total, label))
		if padLen > 2 {
			dots = " " + strings.Repeat(".", padLen-1) + " "
		} else {
			dots = " .. "
		}

		itemStart := time.Now()
		var itemErr error

		switch item.kind {
		case "sast":
			suggestion, err := client.GetSASTRemediation(result.SASTFindings[item.index])
			if err != nil {
				itemErr = err
			} else {
				result.SASTFindings[item.index].AIRemediation = suggestion
			}
		case "leak":
			suggestion, err := client.GetLeakRemediation(
				result.LeakFindings[item.index].Type,
				result.LeakFindings[item.index].File,
			)
			if err != nil {
				itemErr = err
			} else {
				result.LeakFindings[item.index].AIRemediation = suggestion
			}
		}

		elapsed := time.Since(itemStart)

		if itemErr != nil {
			errCount++
			lastErr = itemErr
			fmt.Printf("%s%s%s\n", prefix, dim(dots), color.RedString("\u2717 error"))
		} else if elapsed < 100*time.Millisecond {
			// Very fast = cache hit
			fmt.Printf("%s%s%s\n", prefix, dim(dots), color.GreenString("\u26A1 cached"))
		} else {
			fmt.Printf("%s%s%s\n", prefix, dim(dots), dim(fmt.Sprintf("%.1fs", elapsed.Seconds())))
		}
	}

	totalElapsed := time.Since(totalStart)
	cached := client.CacheHits()
	newCalls := total - errCount - cached

	if errCount > 0 {
		fmt.Printf("\n  %s AI enrichment: %d error(s): %v\n",
			color.YellowString("\u26A0"), errCount, lastErr)
		fmt.Printf("    Tip: check --ai-provider and AI_API_KEY\n")
	}

	// Summary line
	parts := []string{}
	if cached > 0 {
		parts = append(parts, fmt.Sprintf("%d cached", cached))
	}
	if newCalls > 0 {
		parts = append(parts, fmt.Sprintf("%d new", newCalls))
	}

	summary := ""
	if len(parts) > 0 {
		summary = fmt.Sprintf(" (%s)", strings.Join(parts, ", "))
	}

	fmt.Printf("\n  %s AI enrichment complete%s \u2014 %s total\n",
		color.GreenString("\u2713"), summary, dim(fmt.Sprintf("%.1fs", totalElapsed.Seconds())))
}

// detectOllama checks if Ollama is running on the local machine.
// A raw HTTP 200 on port 11434 is not sufficient — any service could be
// bound there. We additionally require the response to decode as the
// /api/tags shape (a JSON object with a "models" array). This prevents
// an unrelated local service from being mistaken for Ollama and having
// prompts forwarded to it.
func detectOllama() bool {
	client := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("refusing redirect during Ollama detection")
		},
	}
	resp, err := client.Get("http://127.0.0.1:11434/api/tags")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	// Cap the body and require it to parse as the Ollama /api/tags shape.
	var payload struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	limited := io.LimitReader(resp.Body, 1*1024*1024)
	if err := json.NewDecoder(limited).Decode(&payload); err != nil {
		return false
	}
	return true
}

// resolveOllamaModel returns the AI model name for display purposes.
func resolveOllamaModel() string {
	if aiModel != "" {
		return aiModel
	}
	return "deepseek-coder"
}
