package cli

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/fatih/color"

	"github.com/filipi86/drogonsec/internal/ui"

	"github.com/filipi86/drogonsec/internal/version"
)

// Environment is injected at build time via ldflags:
//
//	go build -ldflags "-X github.com/filipi86/drogonsec/internal/cli.Environment=development"
//	go build -ldflags "-X github.com/filipi86/drogonsec/internal/cli.Environment=staging"
//
// Empty string (default) = production.
var Environment string

// ansiRE strips ANSI escape codes so we can measure true visual width.
var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// bannerTheme holds the color functions and label for one environment.
type bannerTheme struct {
	frame     func(...interface{}) string // border chars ╔ ═ ║ etc.
	titleText func(...interface{}) string // DROGONSEC ASCII art
	envLabel  string                      // "[DEV]" | "[STAGING]" | ""
}

// resolveTheme returns the correct theme for the current Environment.
func resolveTheme() bannerTheme {
	switch Environment {
	case "development":
		return bannerTheme{
			frame:     color.New(color.FgGreen, color.Bold).SprintFunc(),
			titleText: color.New(color.FgHiCyan, color.Bold).SprintFunc(),
			envLabel:  " [DEV]",
		}
	case "staging":
		return bannerTheme{
			frame:     color.New(color.FgHiYellow, color.Bold).SprintFunc(),
			titleText: color.New(color.FgHiWhite, color.Bold).SprintFunc(),
			envLabel:  " [STAGING]",
		}
	default: // production
		return bannerTheme{
			frame:     color.New(color.FgBlue, color.Bold).SprintFunc(),
			titleText: color.New(color.FgHiYellow, color.Bold).SprintFunc(),
			envLabel:  "",
		}
	}
}

// runeWidth returns the terminal display column-width for a single rune.
// Block elements (█ etc.) and box-drawing characters are single-width in
// standard terminals. Only true East Asian wide characters are double-width,
// but we don't use them in this banner.
func runeWidth(r rune) int {
	return 1
}

// visualLen returns the true terminal display width of s after stripping
// ANSI escape codes and accounting for double-wide block-element chars.
func visualLen(s string) int {
	plain := ansiRE.ReplaceAllString(s, "")
	w := 0
	for _, r := range plain {
		w += runeWidth(r)
	}
	return w
}

// padTo right-pads s with spaces until its visual width equals w.
func padTo(s string, w int) string {
	vl := visualLen(s)
	if vl >= w {
		return s
	}
	return s + strings.Repeat(" ", w-vl)
}

// PrintDrogonBanner prints the DrogonSec cyberpunk banner.
func PrintDrogonBanner() {
	theme := resolveTheme()
	fr := theme.frame
	title := theme.titleText

	// ── Colour palette ────────────────────────────────────────────────────────
	nYel := color.New(color.FgHiYellow, color.Bold).SprintFunc()
	bold := color.New(color.FgHiWhite, color.Bold).SprintFunc()
	dim := color.New(color.FgHiBlack).SprintFunc()
	gn := color.New(color.FgHiGreen, color.Bold).SprintFunc()
	nMag := color.New(color.FgHiMagenta, color.Bold).SprintFunc()

	// ── Frame helpers (W = inner width between ╔ and ╗) ──────────────────────
	// W=80 accommodates the DROGONSEC title lines (≤78 runes wide)
	const W = 80

	topBdr := fr("  ╔") + fr(strings.Repeat("═", W)) + fr("╗")
	midBdr := fr("  ╠") + fr(strings.Repeat("═", W)) + fr("╣")
	botBdr := fr("  ╚") + fr(strings.Repeat("═", W)) + fr("╝")

	// boxLine wraps content in ║…║ using padTo so the right border aligns.
	// inner = W-1: accounts for 1 leading space after ║ (left) + 0 before ║ (right)
	boxLine := func(content string) string {
		return fr("  ║ ") + padTo(content, W-1) + fr("║")
	}

	// centerIn centers content inside a boxLine (accounts for ANSI codes).
	centerIn := func(content string) string {
		vl := visualLen(content)
		pad := (W - 1 - vl) / 2
		if pad < 0 {
			pad = 0
		}
		return strings.Repeat(" ", pad) + content
	}

	ui.Println()
	ui.Println(topBdr)
	ui.Println(boxLine(
		fr("DRG-0x1") + fr(" ▸▸ ") +
			bold("NEURAL THREAT SCANNER") +
			dim("  │  SAST · SCA · LEAKS · GIT-HISTORY · IaC") +
			fr(theme.envLabel)))
	ui.Println(midBdr)

	// ── DROGONSEC — large ASCII title ─────────────────────────────────────────
	ui.Println(boxLine(title(` ██████╗ ██████╗  ██████╗  ██████╗  ██████╗ ███╗  ██╗███████╗███████╗ ██████╗`)))
	ui.Println(boxLine(title(` ██╔══██╗██╔══██╗██╔═══██╗██╔════╝ ██╔═══██╗████╗ ██║██╔════╝██╔════╝██╔════╝`)))
	ui.Println(boxLine(title(` ██║  ██║██████╔╝██║   ██║██║  ███╗██║   ██║██╔██╗██║███████╗█████╗  ██║     `)))
	ui.Println(boxLine(title(` ██║  ██║██╔══██╗██║   ██║██║   ██║██║   ██║██║██╗██║╚════██║██╔══╝  ██║     `)))
	ui.Println(boxLine(title(` ██████╔╝██║  ██║╚██████╔╝╚██████╔╝╚██████╔╝██║╚████║███████║███████╗╚██████╗`)))
	ui.Println(boxLine(title(` ╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝ ╚═══╝╚══════╝╚══════╝ ╚═════╝`)))

	// ── Security statement — centered inside frame ────────────────────────────
	ui.Println(midBdr)
	stmt := nMag("◆") + " " + bold("HUNT VULNERABILITIES") + "  " +
		nMag("◆") + " " + bold("BREAK WALLS") + "  " +
		nMag("◆") + " " + bold("SECURE CODE") + "  " +
		nMag("◆")
	ui.Println(boxLine(centerIn(stmt)))

	// ── Bottom box: capabilities + author tagline ─────────────────────────────
	ui.Println(midBdr)
	ui.Println(boxLine(
		gn("SAST") + dim(" │ ") +
			gn("SCA") + dim(" │ ") +
			gn("LEAKS") + dim(" │ ") +
			gn("GIT-HISTORY") + dim(" │ ") +
			gn("IaC") + dim(" │ ") +
			gn("Remediation AI")))
	ui.Println(boxLine(
		fr("►") + " " +
			nYel("Created by Filipi Pires") +
			dim(" │ "+version.Short()+" │ OWASP 2025 │ ") +
			fr("Maintained by: CROSS-INTEL") +
			" " + fr("◄")))
	ui.Println(botBdr)
	ui.Println()
}

// ── Scan banner ───────────────────────────────────────────────────────────────

// PrintScanBanner prints the graphical header for a scan operation
func PrintScanBanner(path string, sast, sca, leaks, ai bool, format string, enterprise func(...interface{}) string) {
	cyan := color.New(color.FgHiCyan, color.Bold).SprintFunc()
	dim := color.New(color.FgHiBlack).SprintFunc()
	white := color.New(color.FgHiWhite, color.Bold).SprintFunc()

	width := 60
	border := cyan(repeatChar("─", width))

	ui.Println()
	ui.Printf("  %s\n", border)
	ui.Printf("  %s\n", white("Drogonsec Security Scanner"))
	ui.Printf("  %s\n", border)
	ui.Printf("  %s   %s\n", dim("Target"), white(path))
	ui.Printf("  %s\n", border)

	ui.Printf("  %s  %s   %s  %s   %s  %s   %s  %s\n",
		engineDot(sast), engineLabel("SAST", sast),
		engineDot(sca), engineLabel("SCA", sca),
		engineDot(leaks), engineLabel("Leaks", leaks),
		engineDot(ai), aiLabel(ai, enterprise),
	)
	ui.Printf("  %s\n", border)
	ui.Printf("  %s   %s\n", dim("Format"), white(format))
	ui.Printf("  %s\n\n", border)
}

// ── Scan summary ──────────────────────────────────────────────────────────────

// PrintScanSummary prints a graphical summary of scan results
func PrintScanSummary(total, critical, high, medium, low, info int,
	sast, sca, leaks int,
	duration string,
	files int,
	outputFile string,
) {
	cyan := color.New(color.FgHiCyan, color.Bold).SprintFunc()
	white := color.New(color.FgHiWhite, color.Bold).SprintFunc()
	dim := color.New(color.FgHiBlack).SprintFunc()
	bold := color.New(color.Bold).SprintFunc()

	width := 60
	border := cyan(repeatChar("─", width))
	thick := cyan(repeatChar("═", width))

	ui.Println()
	ui.Printf("  %s\n", thick)
	ui.Printf("  %s  %s\n", cyan("📊"), white("SCAN SUMMARY"))
	ui.Printf("  %s\n", thick)

	ui.Printf("  %s %-20s  %s %-15s  %s %s\n",
		dim("Files:"), bold(fmt.Sprintf("%d", files)),
		dim("Duration:"), bold(duration),
		dim("Total:"), bold(fmt.Sprintf("%d", total)),
	)
	ui.Printf("  %s\n", border)

	printVisualBar("  CRITICAL", critical, color.New(color.FgHiRed, color.Bold), "█", 30)
	printVisualBar("  HIGH    ", high, color.New(color.FgRed), "█", 30)
	printVisualBar("  MEDIUM  ", medium, color.New(color.FgHiYellow), "▓", 30)
	printVisualBar("  LOW     ", low, color.New(color.FgCyan), "░", 30)
	printVisualBar("  INFO    ", info, color.New(color.FgHiBlack), "·", 30)

	ui.Printf("  %s\n", border)
	ui.Printf("  %s  %-10s  %s  %-10s  %s  %s\n",
		color.New(color.FgHiYellow).Sprint("⚡ SAST"), bold(fmt.Sprintf("%d", sast)),
		color.New(color.FgHiBlue).Sprint("📦 SCA"), bold(fmt.Sprintf("%d", sca)),
		color.New(color.FgHiRed).Sprint("🔑 Leaks"), bold(fmt.Sprintf("%d", leaks)),
	)
	ui.Printf("  %s\n", thick)

	if critical > 0 {
		ui.Printf("\n  %s\n\n",
			color.New(color.FgHiRed, color.Bold).Sprint("🔴  CRITICAL vulnerabilities detected! Immediate action required."))
	} else if high > 0 {
		ui.Printf("\n  %s\n\n",
			color.New(color.FgRed, color.Bold).Sprint("🟠  HIGH severity vulnerabilities found. Review required."))
	} else if total == 0 {
		ui.Printf("\n  %s\n\n",
			color.New(color.FgHiGreen, color.Bold).Sprint("🟢  Clean! No vulnerabilities found."))
	} else {
		ui.Printf("\n  %s\n\n",
			color.New(color.FgHiYellow, color.Bold).Sprint("🟡  Low/Medium findings. Review when possible."))
	}

	if outputFile != "" {
		ui.Printf("  %s %s\n\n",
			dim("Report saved:"),
			color.New(color.FgHiCyan).Sprint(outputFile),
		)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func repeatChar(ch string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += ch
	}
	return out
}

func engineDot(enabled bool) string {
	if enabled {
		return color.New(color.FgHiGreen, color.Bold).Sprint("●")
	}
	return color.New(color.FgHiBlack).Sprint("○")
}

func engineLabel(name string, enabled bool) string {
	if enabled {
		return color.New(color.FgHiGreen).Sprint(name)
	}
	return color.New(color.FgHiBlack).Sprint(name)
}

func aiLabel(enabled bool, enterprise func(...interface{}) string) string {
	if enabled {
		return enterprise("AI ✦")
	}
	return color.New(color.FgHiBlack).Sprint("AI") + color.New(color.FgMagenta).Sprint(" ✦")
}

func printVisualBar(label string, count int, c *color.Color, char string, maxWidth int) {
	barLen := count
	if barLen > maxWidth {
		barLen = maxWidth
	}
	bar := ""
	for i := 0; i < barLen; i++ {
		bar += char
	}
	countStr := fmt.Sprintf("%3d", count)
	if count > 0 {
		ui.Printf("  %s  %s  %s\n", label, c.Sprint(countStr), c.Sprint(bar))
	} else {
		ui.Printf("  %s  %s\n", label, color.New(color.FgHiBlack).Sprint("  0"))
	}
}
