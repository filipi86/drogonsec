package monitor

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"
	"github.com/filipi86/drogonsec/internal/analyzer"
	"github.com/filipi86/drogonsec/internal/reporter"
)

// cloneAndScan is the core scan trigger: it clones the branch to an isolated
// temp directory, runs the full DrogonSec analysis, writes the report, and
// then unconditionally removes the temp directory.
//
// Security properties:
//   - Temp dir is created with os.MkdirTemp (random suffix, no predictable path).
//   - Cleanup is deferred and runs even if the scan panics.
//   - Report files are created with mode 0o600 (user-only read/write).
//   - The branch name is appended verbatim to the output filename; it has
//     already been validated by ValidateBranchName before reaching here.
func cloneAndScan(cfg *Config, client PlatformClient, branch string) error {
	// Create an isolated workspace with a random suffix.
	tmpDir, err := os.MkdirTemp("", "drogonsec-monitor-*")
	if err != nil {
		return fmt.Errorf("cannot create temp workspace: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			fmt.Printf("  %s Warning: could not remove temp dir %s: %v\n",
				color.YellowString("⚠"), tmpDir, err)
		}
	}()

	start := time.Now()
	fmt.Printf("\n  %s [%s] Scanning branch %s\n",
		color.MagentaString("◆"),
		time.Now().Format("2006-01-02 15:04:05"),
		color.CyanString(branch))

	// Shallow clone — depth 1, single branch.
	if err := shallowClone(client.CloneURL(), branch, tmpDir, client.CloneAuth()); err != nil {
		return fmt.Errorf("git clone failed: %w", err)
	}

	// Copy scan config and point it at the temp workspace.
	scanCfg := *cfg.ScanConfig
	scanCfg.TargetPath = tmpDir

	a := analyzer.New(&scanCfg)
	result, err := a.Run()
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}
	result.Duration = time.Since(start)

	// Build output writer.
	rep, err := reporter.New(scanCfg.OutputFormat)
	if err != nil {
		return err
	}

	output := os.Stdout
	if scanCfg.OutputFile != "" {
		// Stamp each report with branch + timestamp to prevent overwrites.
		// Branch name has already been validated — no injection risk.
		ext := filepath.Ext(scanCfg.OutputFile)
		base := scanCfg.OutputFile[:len(scanCfg.OutputFile)-len(ext)]
		ts := time.Now().Format("20060102-150405")
		fname := fmt.Sprintf("%s_%s_%s%s", base, branch, ts, ext)

		// 0o600 — reports embed vulnerable code; must not be world-readable.
		f, err := os.OpenFile(fname, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("cannot create report file: %w", err)
		}
		defer f.Close()
		output = f
		fmt.Printf("  %s Report written: %s\n", color.GreenString("✓"), fname)
	}

	return rep.Write(result, output)
}
