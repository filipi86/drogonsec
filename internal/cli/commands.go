package cli

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print DragonSec version information",
	Run: func(cmd *cobra.Command, args []string) {
		cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
		fmt.Printf("%s v%s\n", cyan("DragonSec Security Scanner"), "0.1.0")
		fmt.Printf("  Build:    %s\n", "2025-02-17")
		fmt.Printf("  Go:       %s\n", "1.22")
		fmt.Printf("  License:  Apache 2.0\n")
		fmt.Printf("  GitHub:   https://github.com/drogonsec/drogonsec\n")
		fmt.Printf("\n  OWASP Top 10:2025 aligned\n")
		fmt.Printf("  CWE / CVSS 3.1 / SARIF 2.1 support\n")
		fmt.Printf("\n  %s  SAST · SCA · Leaks · IaC   (open-source)\n", color.GreenString("✓"))
		fmt.Printf("  %s  Claude AI remediation        (Enterprise)\n", color.New(color.FgMagenta, color.Bold).Sprint("✦"))
	},
}

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage and list detection rules",
}

var rulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all available rules",
	Run: func(cmd *cobra.Command, args []string) {
		showByLanguage, _ := cmd.Flags().GetBool("by-language")
		showByOWASP, _ := cmd.Flags().GetBool("by-owasp")

		cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
		green := color.New(color.FgGreen).SprintFunc()
		yellow := color.New(color.FgYellow).SprintFunc()

		fmt.Printf("\n%s\n\n", cyan("Available Security Rules"))

		if showByOWASP {
			owaspCategories := []struct {
				id   string
				name string
				rules int
			}{
				{"A01:2025", "Broken Access Control", 23},
				{"A02:2025", "Security Misconfiguration", 31},
				{"A03:2025", "Software Supply Chain Failures", 12},
				{"A04:2025", "Cryptographic Failures", 18},
				{"A05:2025", "Injection", 45},
				{"A06:2025", "Insecure Design", 15},
				{"A07:2025", "Authentication Failures", 20},
				{"A08:2025", "Software or Data Integrity Failures", 9},
				{"A09:2025", "Security Logging & Alerting Failures", 11},
				{"A10:2025", "Mishandling of Exceptional Conditions", 8},
			}
			for _, cat := range owaspCategories {
				fmt.Printf("  %s  %s  %s rules\n",
					yellow(cat.id),
					green(cat.name),
					cyan(fmt.Sprintf("%d", cat.rules)),
				)
			}
		} else if showByLanguage {
			languages := []struct {
				lang  string
				count int
			}{
				{"Java", 28},
				{"Python", 24},
				{"JavaScript", 22},
				{"TypeScript", 22},
				{"Kotlin", 18},
				{"Go", 16},
				{"C#", 20},
				{"PHP", 25},
				{"Ruby", 15},
				{"Swift", 12},
				{"Dart", 10},
				{"Elixir", 8},
				{"Erlang", 6},
				{"Shell", 14},
				{"Terraform/HCL", 19},
				{"Kubernetes", 17},
				{"Nginx", 11},
				{"HTML", 9},
				{"C/C++", 16},
				{"Leaks/Secrets", 47},
			}
			total := 0
			for _, l := range languages {
				fmt.Printf("  %-20s %s rules\n", green(l.lang), cyan(fmt.Sprintf("%d", l.count)))
				total += l.count
			}
			fmt.Printf("\n  %s: %s rules\n", cyan("Total"), yellow(fmt.Sprintf("%d", total)))
		} else {
			fmt.Println("  Use --by-language or --by-owasp to filter rules")
			fmt.Println("  Example: drogonsec rules list --by-language")
		}
		fmt.Println()
	},
}

func init() {
	rulesListCmd.Flags().Bool("by-language", false, "list rules grouped by language")
	rulesListCmd.Flags().Bool("by-owasp", false, "list rules grouped by OWASP category")
	rulesCmd.AddCommand(rulesListCmd)
}
