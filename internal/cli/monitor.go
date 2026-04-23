package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/filipi86/drogonsec/internal/config"
	"github.com/filipi86/drogonsec/internal/monitor"
	"github.com/spf13/cobra"
)

var (
	monPlatform string
	monRepo     string
	monBranch   string
	monMode     string
	monListen   string
	monInterval string
	monTLSCert  string
	monTLSKey   string
	monFmt      string
	monOutput   string
	monSeverity string
	monWorkers  int
	monNoSAST   bool
	monNoSCA    bool
	monNoLeaks  bool
)

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Monitor a remote git branch for security vulnerabilities",
	Long: `Continuously monitor a GitHub or GitLab branch for security issues.

Two modes:

  webhook  Real-time — DrogonSec listens for push events via HTTP.
           Configure a webhook in your repo pointing to this server.
  poll     Periodic  — DrogonSec polls the branch API on a fixed interval
           and scans whenever the HEAD commit changes.

Credentials MUST come from environment variables (never CLI flags):
  GITHUB_TOKEN    GitHub personal access token (scope: repo:read or contents:read)
  GITLAB_TOKEN    GitLab personal access token (scope: read_repository)
  WEBHOOK_SECRET  HMAC-SHA256 key (GitHub) or shared token (GitLab)
                  Required in webhook mode.

Examples:

  # GitHub — webhook mode with TLS
  export GITHUB_TOKEN=ghp_xxxxxxxxxxxx
  export WEBHOOK_SECRET=$(openssl rand -hex 32)
  drogonsec monitor \
    --platform github --repo owner/repo --branch main \
    --mode webhook --listen :8443 \
    --tls-cert cert.pem --tls-key key.pem \
    --format sarif --output /reports/scan.sarif

  # GitLab — polling every 10 minutes
  export GITLAB_TOKEN=glpat-xxxxxxxxxxxx
  drogonsec monitor \
    --platform gitlab --repo group/project --branch develop \
    --mode poll --interval 10m \
    --format json --output /reports/scan.json --severity HIGH
`,
	RunE: runMonitor,
}

func init() {
	monitorCmd.Flags().StringVar(&monPlatform, "platform", "github", "git platform: github | gitlab")
	monitorCmd.Flags().StringVar(&monRepo, "repo", "", "repository slug: owner/repo (required)")
	monitorCmd.Flags().StringVar(&monBranch, "branch", "main", "branch to monitor")
	monitorCmd.Flags().StringVar(&monMode, "mode", "poll", "monitoring mode: webhook | poll")

	// Webhook mode flags.
	monitorCmd.Flags().StringVar(&monListen, "listen", ":8080", "address to listen on (webhook mode)")
	monitorCmd.Flags().StringVar(&monTLSCert, "tls-cert", "", "TLS certificate file (PEM) for HTTPS webhook server")
	monitorCmd.Flags().StringVar(&monTLSKey, "tls-key", "", "TLS private key file (PEM) for HTTPS webhook server")

	// Poll mode flags.
	monitorCmd.Flags().StringVar(&monInterval, "interval", "5m", "polling interval: e.g. 30s, 5m, 1h (min: 30s)")

	// Scan output flags (mirrors scan command for familiarity).
	monitorCmd.Flags().StringVarP(&monFmt, "format", "f", "text", "output format: text, json, sarif, html")
	monitorCmd.Flags().StringVarP(&monOutput, "output", "o", "", "output file base path (branch + timestamp appended per scan)")
	monitorCmd.Flags().StringVar(&monSeverity, "severity", "LOW", "minimum severity to report: LOW, MEDIUM, HIGH, CRITICAL")
	monitorCmd.Flags().IntVar(&monWorkers, "workers", 4, "number of parallel scan workers")
	monitorCmd.Flags().BoolVar(&monNoSAST, "no-sast", false, "disable SAST engine")
	monitorCmd.Flags().BoolVar(&monNoSCA, "no-sca", false, "disable SCA engine")
	monitorCmd.Flags().BoolVar(&monNoLeaks, "no-leaks", false, "disable leak detection")

	_ = monitorCmd.MarkFlagRequired("repo")

	// Tab completion — enum flags only, no filesystem suggestions for sensitive values.
	_ = monitorCmd.RegisterFlagCompletionFunc("platform", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return []string{"github", "gitlab"}, cobra.ShellCompDirectiveNoFileComp
	})
	_ = monitorCmd.RegisterFlagCompletionFunc("mode", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return []string{"webhook", "poll"}, cobra.ShellCompDirectiveNoFileComp
	})
	_ = monitorCmd.RegisterFlagCompletionFunc("format", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return completionFormat, cobra.ShellCompDirectiveNoFileComp
	})
	_ = monitorCmd.RegisterFlagCompletionFunc("severity", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return completionSeverity, cobra.ShellCompDirectiveNoFileComp
	})
	_ = monitorCmd.RegisterFlagCompletionFunc("tls-cert", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return []string{"pem", "crt"}, cobra.ShellCompDirectiveFilterFileExt
	})
	_ = monitorCmd.RegisterFlagCompletionFunc("tls-key", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return []string{"pem", "key"}, cobra.ShellCompDirectiveFilterFileExt
	})
	// Suppress filesystem completion for values that must never come from files.
	for _, f := range []string{"repo", "branch", "listen", "interval", "workers"} {
		_ = monitorCmd.RegisterFlagCompletionFunc(f, cobra.NoFileCompletions)
	}
}

func runMonitor(_ *cobra.Command, _ []string) error {
	// ── Credential resolution ────────────────────────────────────────────────
	// Tokens are read exclusively from the environment to avoid embedding them
	// in shell history, process lists, or CI logs.
	tokenEnv := "GITHUB_TOKEN"
	if monPlatform == "gitlab" {
		tokenEnv = "GITLAB_TOKEN"
	}
	token := os.Getenv(tokenEnv)
	if token == "" {
		return fmt.Errorf("missing %s environment variable\n\n"+
			"  Set it with:  export %s=<your-token>\n"+
			"  Required scope: %s",
			tokenEnv, tokenEnv, requiredScope(monPlatform))
	}

	webhookSecret := os.Getenv("WEBHOOK_SECRET")
	if monMode == "webhook" && webhookSecret == "" {
		return fmt.Errorf("WEBHOOK_SECRET env var is required in webhook mode\n\n" +
			"  Generate one: export WEBHOOK_SECRET=$(openssl rand -hex 32)\n" +
			"  Then configure the same value in your repo's webhook settings")
	}

	// ── Input validation ─────────────────────────────────────────────────────
	if err := monitor.ValidateBranchName(monBranch); err != nil {
		return err
	}
	if err := monitor.ValidateRepoSlug(monRepo); err != nil {
		return err
	}
	if monPlatform != "github" && monPlatform != "gitlab" {
		return fmt.Errorf("unknown platform %q — must be 'github' or 'gitlab'", monPlatform)
	}

	// SSRF health check: confirm the platform API host is in the allowlist and
	// does not resolve to a private/loopback address before any network I/O.
	apiHost, err := monitor.APIHostForPlatform(monPlatform)
	if err != nil {
		return err
	}
	if err := monitor.ValidateAPIHost(apiHost); err != nil {
		return err
	}
	if monMode != "webhook" && monMode != "poll" {
		return fmt.Errorf("unknown mode %q — must be 'webhook' or 'poll'", monMode)
	}

	// ── Interval parsing ─────────────────────────────────────────────────────
	interval := 5 * time.Minute
	if monMode == "poll" {
		d, err := time.ParseDuration(monInterval)
		if err != nil {
			return fmt.Errorf("invalid --interval %q: %w\n  Examples: 30s, 5m, 1h", monInterval, err)
		}
		if d < 30*time.Second {
			return fmt.Errorf("--interval must be at least 30s (got %s)", monInterval)
		}
		interval = d
	}

	// ── Build monitor config ─────────────────────────────────────────────────
	cfg := &monitor.Config{
		Platform:      monitor.Platform(monPlatform),
		Repo:          monRepo,
		Branch:        monBranch,
		Token:         token,
		Mode:          monitor.Mode(monMode),
		ListenAddr:    monListen,
		WebhookSecret: webhookSecret,
		TLSCertFile:   monTLSCert,
		TLSKeyFile:    monTLSKey,
		Interval:      interval,
		ScanConfig: &config.ScanConfig{
			OutputFormat: monFmt,
			OutputFile:   monOutput,
			EnableSAST:   !monNoSAST,
			EnableSCA:    !monNoSCA,
			EnableLeaks:  !monNoLeaks,
			MinSeverity:  monSeverity,
			MaxWorkers:   monWorkers,
		},
	}

	// ── Print session header ─────────────────────────────────────────────────
	bold := color.New(color.FgMagenta, color.Bold).SprintFunc()
	cyan := color.CyanString

	fmt.Printf("\n  %s  Branch Monitor\n", bold("DrogonSec"))
	fmt.Printf("  %-10s %s\n", "Platform:", cyan(monPlatform))
	fmt.Printf("  %-10s %s\n", "Repo:", cyan(monRepo))
	fmt.Printf("  %-10s %s\n", "Branch:", cyan(monBranch))
	fmt.Printf("  %-10s %s\n", "Mode:", cyan(monMode))
	if monMode == "poll" {
		fmt.Printf("  %-10s %s\n", "Interval:", cyan(interval.String()))
	}
	fmt.Println()

	// ── Graceful shutdown ────────────────────────────────────────────────────
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	return monitor.Run(ctx, cfg)
}

func requiredScope(platform string) string {
	if platform == "gitlab" {
		return "read_repository"
	}
	return "repo (or fine-grained: contents:read)"
}
