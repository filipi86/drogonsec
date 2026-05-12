package analyzer

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/filipi86/drogonsec/internal/config"
	"github.com/filipi86/drogonsec/internal/engine"
	"github.com/filipi86/drogonsec/internal/leaks"
	"github.com/filipi86/drogonsec/internal/sca"
	"github.com/schollz/progressbar/v3"
)

// Analyzer is the main orchestrator for all security engines
type Analyzer struct {
	cfg *config.ScanConfig
	mu  sync.Mutex
}

// New creates a new Analyzer instance
func New(cfg *config.ScanConfig) *Analyzer {
	return &Analyzer{cfg: cfg}
}

// Run executes all enabled analysis engines
func (a *Analyzer) Run() (*ScanResult, error) {
	result := &ScanResult{
		TargetPath: a.cfg.TargetPath,
		ScanTime:   time.Now(),
		Version:    "0.1.0",
	}

	// Step 1: Collect files to scan
	fmt.Printf("  %s Discovering files...\n", color.CyanString("→"))
	files, err := a.collectFiles()
	if err != nil {
		return nil, fmt.Errorf("file collection failed: %w", err)
	}
	result.FilesScanned = len(files)

	// Detect languages
	langSet := make(map[string]bool)
	for _, f := range files {
		ext := strings.ToLower(filepath.Ext(f))
		if lang, ok := config.FileExtensionMap[ext]; ok {
			langSet[string(lang)] = true
		}
	}
	for lang := range langSet {
		result.LanguagesFound = append(result.LanguagesFound, lang)
	}

	fmt.Printf("  %s Found %d files across %d languages\n",
		color.GreenString("✓"),
		len(files),
		len(langSet),
	)

	// Step 2: SAST Analysis
	if a.cfg.EnableSAST {
		fmt.Printf("\n  %s Running SAST analysis...\n", color.CyanString("→"))
		if err := a.runSAST(files, result); err != nil {
			fmt.Printf("  %s SAST warning: %v\n", color.YellowString("⚠"), err)
		}
	}

	// Step 3: Leak Detection
	if a.cfg.EnableLeaks {
		fmt.Printf("\n  %s Running leak detection...\n", color.CyanString("→"))
		if err := a.runLeakDetection(files, result); err != nil {
			fmt.Printf("  %s Leak detection warning: %v\n", color.YellowString("⚠"), err)
		}
	}

	// Step 4: SCA Analysis
	if a.cfg.EnableSCA {
		fmt.Printf("\n  %s Running SCA analysis...\n", color.CyanString("→"))
		if err := a.runSCA(result); err != nil {
			fmt.Printf("  %s SCA warning: %v\n", color.YellowString("⚠"), err)
		}
	}

	// Step 5: Compute statistics
	result.ComputeStats()

	// Print summary
	a.printSummary(result)

	return result, nil
}

// collectFiles walks the target path and returns all scannable files
func (a *Analyzer) collectFiles() ([]string, error) {
	var files []string

	ignorePaths := append(config.DefaultIgnorePaths, a.cfg.IgnorePaths...)

	err := filepath.WalkDir(a.cfg.TargetPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable files
		}

		// Check if path should be ignored
		name := d.Name()
		for _, ignore := range ignorePaths {
			if name == ignore || strings.Contains(path, "/"+ignore+"/") {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}

		if d.IsDir() {
			return nil
		}

		// Only include files with known extensions or all files for leak scanning
		ext := strings.ToLower(filepath.Ext(path))
		if _, ok := config.FileExtensionMap[ext]; ok {
			files = append(files, path)
		} else if a.cfg.EnableLeaks {
			// Also scan config/env files for leaks even if not code
			leakExts := map[string]bool{
				".env": true, ".yaml": true, ".yml": true,
				".json": true, ".xml": true, ".conf": true,
				".config": true, ".ini": true, ".properties": true,
				".toml": true, ".txt": true,
			}
			if leakExts[ext] {
				files = append(files, path)
			}
		}

		return nil
	})

	return files, err
}

// runSAST executes the SAST engine on collected files
func (a *Analyzer) runSAST(files []string, result *ScanResult) error {
	bar := progressbar.NewOptions(len(files),
		progressbar.OptionSetDescription("  SAST"),
		progressbar.OptionSetWidth(40),
		progressbar.OptionShowCount(),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "=",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)

	// Clamp workers to at least 1 — zero/negative value would start no
	// goroutines, close findingCh immediately and silently return 0 findings.
	workers := a.cfg.MaxWorkers
	if workers <= 0 {
		workers = 1
	}

	// Worker pool — buffer sized generously to avoid goroutines blocking on
	// send when many findings are produced before the collector drains.
	fileCh := make(chan string, len(files))
	findingCh := make(chan Finding, len(files)*10+100)
	var wg sync.WaitGroup

	// Send files to channel
	for _, f := range files {
		fileCh <- f
	}
	close(fileCh)

	// Start workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sastEngine := engine.NewWithCustomRules(a.cfg.RulesDir)
			for file := range fileCh {
				findings := sastEngine.Analyze(file)
				for _, f := range findings {
					findingCh <- Finding(f)
				}
				bar.Add(1)
			}
		}()
	}

	// Close finding channel when done
	go func() {
		wg.Wait()
		close(findingCh)
	}()

	// Collect findings
	minWeight := config.Severity(a.cfg.MinSeverity).Weight()
	for f := range findingCh {
		if f.Severity.Weight() >= minWeight {
			a.mu.Lock()
			result.AddSASTFinding(f)
			a.mu.Unlock()
		}
	}

	fmt.Printf("\n  %s SAST: %d findings\n",
		color.GreenString("✓"),
		len(result.SASTFindings),
	)
	return nil
}

// runLeakDetection executes the leaks detection engine
func (a *Analyzer) runLeakDetection(files []string, result *ScanResult) error {
	bar := progressbar.NewOptions(len(files),
		progressbar.OptionSetDescription("  Leaks"),
		progressbar.OptionSetWidth(40),
		progressbar.OptionShowCount(),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "=",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)

	detector := leaks.NewDetector()
	// Load .gitignore from the target path so we can downgrade findings on
	// intentionally ignored files (e.g. .env) from HIGH/CRITICAL to INFO,
	// keeping visibility without generating noise (Issue #17).
	gitignore := leaks.NewGitignoreMatcher(a.cfg.TargetPath)

	for _, file := range files {
		findings, err := detector.ScanFile(file)
		if err == nil {
			ignored := gitignore.IsIgnored(file)
			for _, lf := range findings {
				af := leakToFinding(lf)
				if ignored {
					af.Severity = config.SeverityInfo
					af.Description = "[.gitignore] " + af.Description +
						" — file is listed in .gitignore; severity downgraded to INFO. " +
						"If this file was ever committed historically, run `drogonsec scan . --git-history` to check."
				}
				a.mu.Lock()
				result.AddLeakFinding(af)
				a.mu.Unlock()
			}
		}
		bar.Add(1)
	}

	// Git history scan
	if a.cfg.GitHistory {
		fmt.Printf("\n  %s Scanning git history...\n", color.CyanString("→"))
		gitFindings, err := detector.ScanGitHistory(a.cfg.TargetPath)
		if err == nil {
			for _, gf := range gitFindings {
				a.mu.Lock()
				result.AddLeakFinding(leakToFinding(gf))
				a.mu.Unlock()
			}
		}
	}

	fmt.Printf("\n  %s Leaks: %d findings\n",
		color.GreenString("✓"),
		len(result.LeakFindings),
	)
	return nil
}

// runSCA executes the Software Composition Analysis engine
func (a *Analyzer) runSCA(result *ScanResult) error {
	scaEngine := sca.New(a.cfg.TargetPath)
	findings, err := scaEngine.Analyze()
	if err != nil {
		return err
	}

	minWeight := config.Severity(a.cfg.MinSeverity).Weight()
	for _, f := range findings {
		sf := SCAFinding(f)
		if sf.Severity.Weight() >= minWeight {
			a.mu.Lock()
			result.AddSCAFinding(sf)
			a.mu.Unlock()
		}
	}

	fmt.Printf("  %s SCA: %d vulnerable dependencies found\n",
		color.GreenString("✓"),
		len(result.SCAFindings),
	)
	return nil
}

// printSummary outputs a visual summary of findings
func (a *Analyzer) printSummary(result *ScanResult) {
	cyan := color.New(color.FgHiCyan, color.Bold).SprintFunc()
	white := color.New(color.FgHiWhite, color.Bold).SprintFunc()
	dim := color.New(color.FgHiBlack).SprintFunc()
	bold := color.New(color.Bold).SprintFunc()

	thick := cyan(summaryRepeat("═", 62))
	border := cyan(summaryRepeat("─", 62))

	dur := result.Duration.Round(time.Millisecond).String()

	fmt.Println()
	fmt.Printf("  %s\n", thick)
	fmt.Printf("  %s  %s\n", cyan("📊"), white("SCAN SUMMARY"))
	fmt.Printf("  %s\n", thick)
	fmt.Printf("  %s %-18s  %s %-12s  %s %s\n",
		dim("Files:"), bold(fmt.Sprintf("%d", result.FilesScanned)),
		dim("Duration:"), bold(dur),
		dim("Total:"), bold(fmt.Sprintf("%d", result.Stats.TotalFindings)),
	)
	fmt.Printf("  %s\n", border)

	// Visual severity bars
	printSeverityBar("  CRITICAL", result.Stats.CriticalCount, color.New(color.FgHiRed, color.Bold), "█")
	printSeverityBar("  HIGH    ", result.Stats.HighCount, color.New(color.FgRed), "█")
	printSeverityBar("  MEDIUM  ", result.Stats.MediumCount, color.New(color.FgHiYellow), "▓")
	printSeverityBar("  LOW     ", result.Stats.LowCount, color.New(color.FgCyan), "░")
	printSeverityBar("  INFO    ", result.Stats.InfoCount, color.New(color.FgHiBlack), "·")

	fmt.Printf("  %s\n", border)
	fmt.Printf("  %s %-8s   %s %-8s   %s %s\n",
		color.New(color.FgHiYellow).Sprint("⚡ SAST"), bold(fmt.Sprintf("%d", result.Stats.SASTCount)),
		color.New(color.FgHiBlue).Sprint("📦 SCA"), bold(fmt.Sprintf("%d", result.Stats.SCACount)),
		color.New(color.FgHiRed).Sprint("🔑 Leaks"), bold(fmt.Sprintf("%d", result.Stats.LeaksCount)),
	)
	fmt.Printf("  %s\n", thick)

	// Verdict
	switch {
	case result.Stats.CriticalCount > 0:
		fmt.Printf("\n  %s\n\n", color.New(color.FgHiRed, color.Bold).Sprint(
			"🔴  CRITICAL vulnerabilities detected! Immediate action required."))
	case result.Stats.HighCount > 0:
		fmt.Printf("\n  %s\n\n", color.New(color.FgRed, color.Bold).Sprint(
			"🟠  HIGH severity vulnerabilities found. Review required."))
	case result.Stats.TotalFindings == 0:
		fmt.Printf("\n  %s\n\n", color.New(color.FgHiGreen, color.Bold).Sprint(
			"🟢  Clean! No vulnerabilities found."))
	default:
		fmt.Printf("\n  %s\n\n", color.New(color.FgHiYellow, color.Bold).Sprint(
			"🟡  Low/Medium findings. Review when possible."))
	}

	if _, err := os.Stat(a.cfg.TargetPath); err == nil && a.cfg.OutputFile != "" {
		fmt.Printf("  %s %s\n\n",
			dim("Report saved:"),
			color.New(color.FgHiCyan).Sprint(a.cfg.OutputFile),
		)
	}
}

func summaryRepeat(ch string, n int) string {
	// strings.Repeat is O(n) via a single allocation; += in a loop is O(n²).
	return strings.Repeat(ch, n)
}

func printSeverityBar(label string, count int, c *color.Color, char string) {
	maxBar := 30
	barLen := count
	if barLen > maxBar {
		barLen = maxBar
	}
	bar := ""
	for i := 0; i < barLen; i++ {
		bar += char
	}
	if count > 0 {
		fmt.Printf("  %s  %s  %s\n", label, c.Sprintf("%3d", count), c.Sprint(bar))
	} else {
		fmt.Printf("  %s  %s\n", label, color.New(color.FgHiBlack).Sprint("  0"))
	}
}

// leakToFinding converts a leaks.LeakFinding to analyzer.LeakFinding
func leakToFinding(lf leaks.LeakFinding) LeakFinding {
	return LeakFinding{
		Type:         lf.Type,
		File:         lf.File,
		Line:         lf.Line,
		Match:        lf.Match,
		RuleID:       lf.RuleID,
		Severity:     lf.Severity,
		Description:  lf.Description,
		Entropy:      lf.Entropy,
		InGitHistory: lf.InGitHistory,
		CommitHash:   lf.CommitHash,
	}
}
