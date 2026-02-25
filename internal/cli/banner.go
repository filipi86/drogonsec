package cli

import (
	"fmt"

	"github.com/fatih/color"
)

// PrintDragonBanner prints the DragonSec banner with ASCII dragon and fire
func PrintDragonBanner() {
	// Color palette
	dragonGreen  := color.New(color.FgGreen, color.Bold).SprintFunc()
	dragonCyan   := color.New(color.FgCyan).SprintFunc()
	fireRed      := color.New(color.FgHiRed, color.Bold).SprintFunc()
	fireOrange   := color.New(color.FgYellow, color.Bold).SprintFunc()
	fireYellow   := color.New(color.FgHiYellow).SprintFunc()
	titleCyan    := color.New(color.FgHiCyan, color.Bold).SprintFunc()
	titleWhite   := color.New(color.FgHiWhite, color.Bold).SprintFunc()
	dimGray      := color.New(color.FgHiBlack).SprintFunc()
	red          := color.New(color.FgHiRed).SprintFunc()
	green        := color.New(color.FgHiGreen).SprintFunc()

	fmt.Println()

	// Dragon lines (left side) + fire + title (right side)
	// Dragon body in green, fire in red→orange→yellow gradient
	fmt.Printf("  %s\n",
		dragonGreen(`          __          `))

	fmt.Printf("  %s%s\n",
		dragonGreen(`       _,( ),_,       `),
		fireRed(`  ))  `))

	fmt.Printf("  %s%s  %s\n",
		dragonGreen(`     ,( ) (   ) `,),
		fireRed(`)))))`),
		titleCyan(`  ██████╗ ██████╗  ██████╗  ██████╗  ██╗  ██╗`))

	fmt.Printf("  %s%s  %s\n",
		dragonGreen(`    ( )  (   )  `),
		fireOrange(`))))))`),
		titleCyan(`  ██╔══██╗██╔══██╗██╔═══██╗██╔════╝  ██║  ██║`))

	fmt.Printf("  %s  %s  %s\n",
		dragonGreen(`   |  o  o  ;`),
		fireOrange(`))))))`),
		titleCyan(`  ██║  ██║██████╔╝██║   ██║██║  ███╗  ██║  ██║`))

	fmt.Printf("  %s%s  %s\n",
		dragonGreen(`   |  ___  < `),
		fireYellow(`>>>>>>>`),
		titleCyan(`  ██║  ██║██╔══██╗██║   ██║██║   ██║  ╚██╗██╔╝`))

	fmt.Printf("  %s%s  %s\n",
		dragonGreen(`   \ \___/ / `),
		fireYellow(`>>>>>>>`),
		titleCyan(`  ██████╔╝██║  ██║╚██████╔╝╚██████╔╝   ╚███╔╝ `))

	fmt.Printf("  %s%s  %s\n",
		dragonGreen(`    '-. .-'  `),
		fireOrange(`))))))`),
		titleCyan(`  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝     ╚══╝  `))

	fmt.Printf("  %s%s\n",
		dragonGreen(`   /  | |  \ `),
		fireRed(`  )))  `))

	fmt.Printf("  %s%s  %s\n",
		dragonCyan(`  / /  | |  \ \`),
		fireRed(`))`),
		titleWhite(`   Security Scanner`))

	fmt.Printf("  %s         %s\n",
		dragonCyan(` /_/   |_|   \_\`),
		dimGray(`v0.1.0 · Apache 2.0 · OWASP 2025`))

	fmt.Println()

	// Bottom divider with engine status
	line := titleCyan("  ─────────────────────────────────────────────────────────────")
	fmt.Println(line)
	fmt.Printf("  %s  %s  %s  %s\n",
		green("● SAST"),
		green("● SCA"),
		green("● Leaks"),
		green("● IaC"),
	)
	fmt.Printf("  %s  %s\n",
		red("◆ OWASP Top 10:2025"),
		dimGray("CWE · CVSS 3.1 · SARIF 2.1"),
	)
	fmt.Println(line)
	fmt.Println()
}

// PrintScanBanner prints the graphical header for a scan operation
func PrintScanBanner(path string, sast, sca, leaks, ai bool, format string, enterprise func(...interface{}) string) {
	cyan  := color.New(color.FgHiCyan, color.Bold).SprintFunc()
	dim   := color.New(color.FgHiBlack).SprintFunc()
	white := color.New(color.FgHiWhite, color.Bold).SprintFunc()

	width := 60
	border := cyan(repeatChar("─", width))

	fmt.Println()
	fmt.Printf("  %s\n", border)
	fmt.Printf("  %s  %s\n", cyan("🐉"), white("DragonSec Security Scanner"))
	fmt.Printf("  %s\n", border)
	fmt.Printf("  %s  %s\n", dim("Target"), white(path))
	fmt.Printf("  %s\n", border)

	// Engine status row
	fmt.Printf("  %s  %s   %s  %s   %s  %s   %s  %s\n",
		engineDot(sast), engineLabel("SAST", sast),
		engineDot(sca),  engineLabel("SCA", sca),
		engineDot(leaks),engineLabel("Leaks", leaks),
		engineDot(ai),   aiLabel(ai, enterprise),
	)
	fmt.Printf("  %s\n", border)
	fmt.Printf("  %s %s\n", dim("Format"), white(format))
	fmt.Printf("  %s\n\n", border)
}

// PrintScanSummary prints a graphical summary of scan results
func PrintScanSummary(total, critical, high, medium, low, info int,
	sast, sca, leaks int,
	duration string,
	files int,
	outputFile string,
) {
	cyan     := color.New(color.FgHiCyan, color.Bold).SprintFunc()
	white    := color.New(color.FgHiWhite, color.Bold).SprintFunc()
	dim      := color.New(color.FgHiBlack).SprintFunc()
	bold     := color.New(color.Bold).SprintFunc()

	width := 60
	border := cyan(repeatChar("─", width))
	thick  := cyan(repeatChar("═", width))

	fmt.Println()
	fmt.Printf("  %s\n", thick)
	fmt.Printf("  %s  %s\n", cyan("📊"), white("SCAN SUMMARY"))
	fmt.Printf("  %s\n", thick)

	// Stats row
	fmt.Printf("  %s %-20s  %s %-15s  %s %s\n",
		dim("Files:"),  bold(fmt.Sprintf("%d", files)),
		dim("Duration:"), bold(duration),
		dim("Total:"),  bold(fmt.Sprintf("%d", total)),
	)
	fmt.Printf("  %s\n", border)

	// Severity breakdown with visual bars
	printVisualBar("  CRITICAL", critical, color.New(color.FgHiRed, color.Bold),   "█", 30)
	printVisualBar("  HIGH    ", high,     color.New(color.FgRed),                  "█", 30)
	printVisualBar("  MEDIUM  ", medium,   color.New(color.FgHiYellow),             "▓", 30)
	printVisualBar("  LOW     ", low,      color.New(color.FgCyan),                 "░", 30)
	printVisualBar("  INFO    ", info,     color.New(color.FgHiBlack),              "·", 30)

	fmt.Printf("  %s\n", border)

	// Engine findings row
	fmt.Printf("  %s  %-10s  %s  %-10s  %s  %s\n",
		color.New(color.FgHiYellow).Sprint("⚡ SAST"),   bold(fmt.Sprintf("%d", sast)),
		color.New(color.FgHiBlue).Sprint("📦 SCA"),    bold(fmt.Sprintf("%d", sca)),
		color.New(color.FgHiRed).Sprint("🔑 Leaks"),  bold(fmt.Sprintf("%d", leaks)),
	)
	fmt.Printf("  %s\n", thick)

	// Final verdict
	if critical > 0 {
		fmt.Printf("\n  %s\n\n",
			color.New(color.FgHiRed, color.Bold).Sprint("🔴  CRITICAL vulnerabilities detected! Immediate action required."),
		)
	} else if high > 0 {
		fmt.Printf("\n  %s\n\n",
			color.New(color.FgRed, color.Bold).Sprint("🟠  HIGH severity vulnerabilities found. Review required."),
		)
	} else if total == 0 {
		fmt.Printf("\n  %s\n\n",
			color.New(color.FgHiGreen, color.Bold).Sprint("🟢  Clean! No vulnerabilities found."),
		)
	} else {
		fmt.Printf("\n  %s\n\n",
			color.New(color.FgHiYellow, color.Bold).Sprint("🟡  Low/Medium findings. Review when possible."),
		)
	}

	if outputFile != "" {
		fmt.Printf("  %s %s\n\n",
			dim("Report saved:"),
			color.New(color.FgHiCyan).Sprint(outputFile),
		)
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────────

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
		fmt.Printf("  %s  %s  %s\n", label, c.Sprint(countStr), c.Sprint(bar))
	} else {
		fmt.Printf("  %s  %s\n", label, color.New(color.FgHiBlack).Sprint("  0"))
	}
}
