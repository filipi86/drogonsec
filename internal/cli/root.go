package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/filipi86/drogonsec/internal/version"
)

var (
	cfgFile string
	verbose bool
)

var rootCmd = &cobra.Command{
	Use:   "drogonsec",
	Short: "DrogonSec - Security Static Analysis & SCA Tool",
	Long: fmt.Sprintf(`%s
  Open-source SAST · SCA · Secret Detection · IaC Security
  OWASP Top 10:2025 · CWE · CVSS 3.1 · SARIF 2.1

  %s  drogonsec scan .
       drogonsec scan ./project --format html --output report.html
       drogonsec scan . --severity HIGH

  GitHub: https://github.com/filipi86/drogonsec`,
		color.New(color.FgHiCyan, color.Bold).Sprint("DrogonSec Security Scanner "+version.String()),
		color.New(color.FgHiBlack).Sprint("Usage:"),
	),
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Skip the banner for completion commands and Cobra's hidden
		// __complete/__completeNoDesc helpers — printing it there would
		// pollute shell-completion output with the banner's lines.
		name := cmd.Name()
		if name == "completion" || strings.HasPrefix(name, "__complete") {
			return
		}
		PrintDrogonBanner()
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: .drogonsec.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

	// Tab-complete --config only with .yaml/.yml files.
	_ = rootCmd.RegisterFlagCompletionFunc("config", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return []string{"yaml", "yml"}, cobra.ShellCompDirectiveFilterFileExt
	})

	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))

	// Show banner on -h / --help for all commands.
	// PersistentPreRun handles banner for normal execution; Cobra skips
	// PreRun hooks for help, so we override HelpFunc here instead.
	origHelp := rootCmd.HelpFunc()
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		PrintDrogonBanner()
		origHelp(cmd, args)
	})

	// Register sub-commands
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(monitorCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(rulesCmd)
	rootCmd.AddCommand(completionCmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err == nil {
			viper.AddConfigPath(home)
		}
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".drogonsec")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		if verbose {
			fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		}
	}
}
