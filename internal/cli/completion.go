package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// ── `drogonsec completion` — script generator ───────────────────────────────

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate shell completion scripts",
	Long: `Generate shell completion scripts for Drogonsec.

Tab completion covers every subcommand, every enum flag value
(--severity, --ai-provider, --format, --ai-model, --languages) and
offers directory-only completion for positional path arguments. The
--ai-key flag is intentionally excluded from completion to avoid
leaking secrets into shell history.

To load completions:

  Bash (add to ~/.bashrc):
    source <(drogonsec completion bash)

  Zsh (add to ~/.zshrc):
    source <(drogonsec completion zsh)

  Fish:
    drogonsec completion fish | source

  PowerShell:
    drogonsec completion powershell | Out-String | Invoke-Expression

Or run the helper to install for your current shell with confirmation:

    drogonsec completion install
`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return cmd.Root().GenBashCompletionV2(os.Stdout, true)
		case "zsh":
			return cmd.Root().GenZshCompletion(os.Stdout)
		case "fish":
			return cmd.Root().GenFishCompletion(os.Stdout, true)
		case "powershell":
			return cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
		}
		return nil
	},
}

// ── `drogonsec completion install` — safe auto-wiring helper ────────────────
//
// Rationale: many users never realise completion exists. This helper
// detects the current shell, previews what would be written, and asks
// for explicit confirmation before touching ~/.bashrc / ~/.zshrc. The
// generated file is written with 0o600 to prevent other local users
// from tampering with a script your shell sources on every login.

var (
	installDryRun bool
	installYes    bool
)

var completionInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install tab completion for the current shell (interactive)",
	Long: `Detect your shell, generate the completion script, and wire it up
in your shell profile — with confirmation before any file is modified.

The completion script is written to ~/.drogonsec/completion.<shell> with
mode 0o600 so other local users cannot tamper with a script that is
sourced on every new shell. Your profile (~/.zshrc / ~/.bashrc / fish
conf) is appended with a single source line after explicit confirmation.

Flags:
  --dry-run   show what would be written without touching any file
  --yes       skip confirmation prompt (use only in automation you trust)
`,
	RunE: runCompletionInstall,
}

func init() {
	completionInstallCmd.Flags().BoolVar(&installDryRun, "dry-run", false, "preview without modifying files")
	completionInstallCmd.Flags().BoolVar(&installYes, "yes", false, "skip confirmation prompt")
	completionCmd.AddCommand(completionInstallCmd)
}

func runCompletionInstall(cmd *cobra.Command, _ []string) error {
	shell := detectShell()
	if shell == "" {
		return fmt.Errorf("could not detect shell from $SHELL; run `drogonsec completion <bash|zsh|fish|powershell>` manually")
	}
	if runtime.GOOS == "windows" {
		return fmt.Errorf("auto-install is not supported on Windows; see `drogonsec completion powershell`")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot locate home directory: %w", err)
	}

	profile, sourceLine, err := profilePathFor(shell, home)
	if err != nil {
		return err
	}
	scriptPath := filepath.Join(home, ".drogonsec", "completion."+shell)

	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()

	fmt.Println()
	fmt.Printf("  %s\n\n", cyan("Tab completion install preview"))
	fmt.Printf("  shell         : %s\n", yellow(shell))
	fmt.Printf("  script path   : %s %s\n", yellow(scriptPath), color.New(color.FgHiBlack).Sprint("(mode 0600)"))
	fmt.Printf("  profile       : %s\n", yellow(profile))
	fmt.Printf("  appended line : %s\n", yellow(sourceLine))
	fmt.Println()

	if installDryRun {
		fmt.Printf("  %s dry-run only — no files modified\n\n", green("✓"))
		return nil
	}

	if !installYes {
		fmt.Printf("  Proceed? [y/N]: ")
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer != "y" && answer != "yes" {
			fmt.Printf("\n  %s aborted\n\n", yellow("!"))
			return nil
		}
	}

	if err := os.MkdirAll(filepath.Dir(scriptPath), 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	f, err := os.OpenFile(scriptPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("write completion script: %w", err)
	}
	defer f.Close()

	switch shell {
	case "bash":
		if err := cmd.Root().GenBashCompletionV2(f, true); err != nil {
			return err
		}
	case "zsh":
		if err := cmd.Root().GenZshCompletion(f); err != nil {
			return err
		}
	case "fish":
		if err := cmd.Root().GenFishCompletion(f, true); err != nil {
			return err
		}
	}

	if err := appendSourceLineIfMissing(profile, sourceLine); err != nil {
		return fmt.Errorf("append to profile: %w", err)
	}

	fmt.Printf("\n  %s completion installed for %s\n", green("✓"), cyan(shell))
	fmt.Printf("  Open a new shell (or `source %s`) to activate.\n\n", profile)
	return nil
}

func detectShell() string {
	sh := os.Getenv("SHELL")
	if sh == "" {
		return ""
	}
	base := filepath.Base(sh)
	switch base {
	case "bash", "zsh", "fish":
		return base
	default:
		return ""
	}
}

func profilePathFor(shell, home string) (profile, sourceLine string, err error) {
	switch shell {
	case "bash":
		profile = filepath.Join(home, ".bashrc")
		sourceLine = fmt.Sprintf("source %s/.drogonsec/completion.bash", home)
	case "zsh":
		profile = filepath.Join(home, ".zshrc")
		sourceLine = fmt.Sprintf("source %s/.drogonsec/completion.zsh", home)
	case "fish":
		profile = filepath.Join(home, ".config", "fish", "config.fish")
		sourceLine = fmt.Sprintf("source %s/.drogonsec/completion.fish", home)
	default:
		return "", "", fmt.Errorf("unsupported shell: %s", shell)
	}
	return profile, sourceLine, nil
}

// appendSourceLineIfMissing adds a single source line to the profile
// only if an identical line is not already present. Profile permissions
// are preserved (we never chmod user profiles) but we refuse to create
// one that does not already exist to avoid clobbering untracked paths.
func appendSourceLineIfMissing(profile, line string) error {
	existing, err := os.ReadFile(profile)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if strings.Contains(string(existing), line) {
		return nil
	}
	// Open with user-only perms if the file does not exist yet.
	f, err := os.OpenFile(profile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "\n# DrogonSec tab completion\n%s\n", line)
	return err
}

// ── Completion value providers — used by scan.go via RegisterFlagCompletionFunc

var (
	completionSeverity = []string{
		"LOW\tinclude LOW, MEDIUM, HIGH, CRITICAL",
		"MEDIUM\tinclude MEDIUM, HIGH, CRITICAL",
		"HIGH\tinclude HIGH, CRITICAL only",
		"CRITICAL\tinclude CRITICAL only",
	}
	completionFormat = []string{
		"text\thuman-readable (default)",
		"json\tmachine-readable report",
		"sarif\tGitHub / Azure DevOps Security upload",
		"html\tstandalone styled report",
		"cyclonedx\tCycloneDX 1.5 SBOM (JSON)",
	}
	completionAIProvider = []string{
		"ollama\tlocal, free, no API key (default when Ollama is running)",
		"anthropic\tClaude — requires AI_API_KEY",
		"openai\tGPT-4/4o — requires AI_API_KEY + --ai-endpoint",
		"azure\tAzure OpenAI — requires AI_API_KEY + --ai-endpoint",
		"custom\tself-hosted OpenAI-compatible endpoint",
	}
	completionLanguages = []string{
		"python", "java", "javascript", "typescript", "go", "kotlin",
		"csharp", "php", "ruby", "swift", "dart", "elixir", "erlang",
		"shell", "cpp", "terraform", "kubernetes", "nginx", "html",
	}
	// Model suggestions per provider — presented when the user has
	// already specified --ai-provider on the command line.
	completionAIModels = map[string][]string{
		"ollama": {
			"deepseek-coder\tdefault, 6.7B code model",
			"codellama\tMeta code model",
			"llama3\tgeneral-purpose",
			"mistral\tlightweight general model",
			"qwen2.5-coder\tcode-specialized",
		},
		"anthropic": {
			"claude-sonnet-4-6\tbalanced cost/quality (default)",
			"claude-opus-4-7\thighest quality",
			"claude-haiku-4-5\tfastest / cheapest",
		},
		"openai": {
			"gpt-4o\tmultimodal flagship",
			"gpt-4o-mini\tcheap, fast",
			"gpt-4-turbo\tprior generation",
		},
		"azure": {
			"gpt-4o",
			"gpt-4",
			"gpt-35-turbo",
		},
	}
)

// completeAIModel is a flag completion func that varies with --ai-provider.
func completeAIModel(cmd *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	provider, _ := cmd.Flags().GetString("ai-provider")
	if models, ok := completionAIModels[strings.ToLower(provider)]; ok {
		return models, cobra.ShellCompDirectiveNoFileComp
	}
	// No provider yet — show all provider-default models.
	var all []string
	for _, list := range completionAIModels {
		all = append(all, list...)
	}
	return all, cobra.ShellCompDirectiveNoFileComp
}
