package cli

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

// PrintDragonBanner prints the DrogonSec cyberpunk banner:
// angular dragon breathing fire at a crumbling wall.
func PrintDragonBanner() {

	// ── Colour palette ────────────────────────────────────────────────────────
	nCyan  := color.New(color.FgHiCyan, color.Bold).SprintFunc()
	nMag   := color.New(color.FgHiMagenta, color.Bold).SprintFunc()
	nYel   := color.New(color.FgHiYellow, color.Bold).SprintFunc()
	fRed   := color.New(color.FgHiRed, color.Bold).SprintFunc()
	fOra   := color.New(color.FgYellow, color.Bold).SprintFunc()
	fYel   := color.New(color.FgHiYellow).SprintFunc()
	drg    := color.New(color.FgHiCyan).SprintFunc()
	drgB   := color.New(color.FgHiCyan, color.Bold).SprintFunc()
	wll    := color.New(color.FgHiBlack, color.Bold).SprintFunc()
	wCrk   := color.New(color.FgRed, color.Bold).SprintFunc()
	wRub   := color.New(color.FgRed).SprintFunc()
	bold   := color.New(color.FgHiWhite, color.Bold).SprintFunc()
	dim    := color.New(color.FgHiBlack).SprintFunc()
	gn     := color.New(color.FgHiGreen, color.Bold).SprintFunc()
	title  := color.New(color.FgHiCyan, color.Bold).SprintFunc()

	// ── Borders ───────────────────────────────────────────────────────────────
	top := nCyan("  ╔══[ ") + nMag("DRG-0x1") + nCyan(" ]") +
		nCyan(strings.Repeat("═", 12)) +
		nCyan("[ ") + bold("NEURAL THREAT SCANNER") + nCyan(" ]") +
		nCyan(strings.Repeat("═", 27)) + nCyan("╗")

	mid := nCyan("  ╠") + nCyan(strings.Repeat("═", 76)) + nCyan("╣")
	bot := nCyan("  ╚") + nCyan(strings.Repeat("═", 76)) + nCyan("╝")

	fmt.Println()
	fmt.Println(top)
	fmt.Println(mid)
	fmt.Println()

	// ── Dragon · Fire · Broken-Wall scene ────────────────────────────────────
	//
	//   Dragon (angular, sharp)   Fire breath (▓▒░ gradient)   Broken wall
	//
	//       ▄╦══╦═╗                                            ╔══╗  ╔══╗
	//     ╔══╬██╬═╬══╗     ▓▓▓▒▒░░░                ░░▒▒▓▓▓    ║  ╚══╝  ║
	//     ║  ╠██╬═╬╗ ╚═══════════════════════════►  ░░▒▒▓▓▓    ╠══╗  ╔══╣
	//     ║  ╚══╩═╝╚═╗                              ░░▒▒▓▒░    ╚══╝  ╚══╝
	//     ╚══╗ ╔════╝ ╔═╗                           ░▒▒▓░  ░    ░╔╗░  ░╔╗
	//        ╚═╩══════╝ ╚═╗                         ▒▒▓░░  ░░    ╚╝    ╚╝
	//           ║╗   ║╗   ║                         ▒▓░░         [BREACH]
	//           ╚╝   ╚╝   ╝

	// Row 1 — dragon head (horn + snout)
	fmt.Printf("         %s                                              %s  %s\n",
		drgB("▄╦══╦═╗"),
		wll("│▓▓█"),
		wll("╔══╗  ╔══╗"))

	// Row 2 — neck + first jet of fire
	fmt.Printf("       %s   %s%s%s%s              %s  %s\n",
		drgB("╔══╬██╬═╬══╗"),
		fRed("▓▓▓"),
		fRed("▒▒▒"),
		fOra("░░░"),
		fYel("░░"),
		wll("│▓▓█"),
		wll("║  ╚══╝  ║"))

	// Row 3 — body + full fire breath ════► wall
	fmt.Printf("       %s%s%s%s%s%s   %s  %s\n",
		drgB("║  ╠██╬═╬╗ ╚══"),
		fRed("▓▓▓"),
		fRed("▒▒▒"),
		fOra("▒▒░"),
		fOra("░░░"),
		fYel("░░░░░░░░░░░░░░►"),
		wll("│▓▓█"),
		wCrk("╠══╗  ╔══╣"))

	// Row 4 — belly / tail base
	fmt.Printf("       %s                                  %s  %s\n",
		drg("║  ╚══╩═╝╚═╗"),
		wll("│▒▒░"),
		wCrk("╚══╝  ╚══╝"))

	// Row 5 — tail + folded wing
	fmt.Printf("       %s                                  %s  %s\n",
		drg("╚══╗  ╔════╝  ╔═╗"),
		wll("│░░░"),
		wRub("░  ╔╗░  ╔╗░"))

	// Row 6 — wing tip + hind leg
	fmt.Printf("          %s                               %s  %s\n",
		drg("╚══╩══════════╝"),
		wll("│░░░"),
		wRub("░  ╚╝░  ╚╝"))

	// Row 7 — feet + rubble
	fmt.Printf("            %s  %s                         %s  %s\n",
		drg("╔╗"), drg("╔╗"),
		wll("│░░ "),
		wRub("░░░░░░░░░"))

	// Row 8 — ground line + breach label
	fmt.Printf("            %s  %s                         %s  %s\n",
		drg("╚╝"), drg("╚╝"),
		wll("│   "),
		wCrk("[ BREACH DETECTED ]"))

	fmt.Println()
	fmt.Println(mid)
	fmt.Println()

	// ── DROGONSEC — big ASCII title ───────────────────────────────────────────
	fmt.Println("  " + title(` ██████╗ ██████╗  ██████╗  ██████╗  ██████╗ ███╗  ██╗███████╗███████╗ ██████╗`))
	fmt.Println("  " + title(` ██╔══██╗██╔══██╗██╔═══██╗██╔════╝ ██╔═══██╗████╗ ██║██╔════╝██╔════╝██╔════╝`))
	fmt.Println("  " + title(` ██║  ██║██████╔╝██║   ██║██║  ███╗██║   ██║██╔██╗██║███████╗█████╗  ██║     `))
	fmt.Println("  " + title(` ██║  ██║██╔══██╗██║   ██║██║   ██║██║   ██║██║╚██╗██║╚════██║██╔══╝  ██║     `))
	fmt.Println("  " + title(` ██████╔╝██║  ██║╚██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║███████║███████╗╚██████╗`))
	fmt.Println("  " + title(` ╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝`))

	fmt.Println()

	// ── Security statement ────────────────────────────────────────────────────
	fmt.Printf("  %s %s  %s %s  %s %s  %s\n",
		nMag("◆"), bold("HUNT VULNERABILITIES"),
		nMag("◆"), bold("BREAK WALLS"),
		nMag("◆"), bold("SECURE CODE"),
		nMag("◆"))

	fmt.Println()

	// ── Capabilities bar ──────────────────────────────────────────────────────
	sep := "  " + dim(strings.Repeat("─", 74))
	fmt.Println(sep)
	fmt.Printf("  %s  %s  %s  %s  %s  %s  %s  %s  %s  %s  %s\n",
		gn("SAST"), dim("│"),
		gn("SCA"), dim("│"),
		gn("LEAKS"), dim("│"),
		gn("GIT-HISTORY"), dim("│"),
		gn("IaC"), dim("│"),
		nMag("Claude AI [Enterprise]"))
	fmt.Println(sep)

	// ── Author tagline ────────────────────────────────────────────────────────
	fmt.Printf("  %s %s  %s  %s  %s  %s\n",
		nCyan("►"),
		nYel("By Filipi Pires"),
		dim("│  v0.1.0  │  OWASP Top 10:2025  │  Apache 2.0"),
		dim("│"),
		nMag("Author: Filipi Pires"),
		nCyan("◄"))

	fmt.Println(bot)
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
		engineDot(leaks), engineLabel("Leaks", leaks),
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
	cyan  := color.New(color.FgHiCyan, color.Bold).SprintFunc()
	white := color.New(color.FgHiWhite, color.Bold).SprintFunc()
	dim   := color.New(color.FgHiBlack).SprintFunc()
	bold  := color.New(color.Bold).SprintFunc()

	width := 60
	border := cyan(repeatChar("─", width))
	thick  := cyan(repeatChar("═", width))

	fmt.Println()
	fmt.Printf("  %s\n", thick)
	fmt.Printf("  %s  %s\n", cyan("📊"), white("SCAN SUMMARY"))
	fmt.Printf("  %s\n", thick)

	fmt.Printf("  %s %-20s  %s %-15s  %s %s\n",
		dim("Files:"), bold(fmt.Sprintf("%d", files)),
		dim("Duration:"), bold(duration),
		dim("Total:"), bold(fmt.Sprintf("%d", total)),
	)
	fmt.Printf("  %s\n", border)

	printVisualBar("  CRITICAL", critical, color.New(color.FgHiRed, color.Bold), "█", 30)
	printVisualBar("  HIGH    ", high,     color.New(color.FgRed),               "█", 30)
	printVisualBar("  MEDIUM  ", medium,   color.New(color.FgHiYellow),          "▓", 30)
	printVisualBar("  LOW     ", low,      color.New(color.FgCyan),              "░", 30)
	printVisualBar("  INFO    ", info,     color.New(color.FgHiBlack),           "·", 30)

	fmt.Printf("  %s\n", border)
	fmt.Printf("  %s  %-10s  %s  %-10s  %s  %s\n",
		color.New(color.FgHiYellow).Sprint("⚡ SAST"),  bold(fmt.Sprintf("%d", sast)),
		color.New(color.FgHiBlue).Sprint("📦 SCA"),   bold(fmt.Sprintf("%d", sca)),
		color.New(color.FgHiRed).Sprint("🔑 Leaks"), bold(fmt.Sprintf("%d", leaks)),
	)
	fmt.Printf("  %s\n", thick)

	if critical > 0 {
		fmt.Printf("\n  %s\n\n",
			color.New(color.FgHiRed, color.Bold).Sprint("🔴  CRITICAL vulnerabilities detected! Immediate action required."))
	} else if high > 0 {
		fmt.Printf("\n  %s\n\n",
			color.New(color.FgRed, color.Bold).Sprint("🟠  HIGH severity vulnerabilities found. Review required."))
	} else if total == 0 {
		fmt.Printf("\n  %s\n\n",
			color.New(color.FgHiGreen, color.Bold).Sprint("🟢  Clean! No vulnerabilities found."))
	} else {
		fmt.Printf("\n  %s\n\n",
			color.New(color.FgHiYellow, color.Bold).Sprint("🟡  Low/Medium findings. Review when possible."))
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
