package monitor

import (
	"context"
	"fmt"
	"time"

	"github.com/fatih/color"
	"github.com/filipi86/drogonsec/internal/ui"
)

type poller struct {
	cfg     *Config
	client  PlatformClient
	scanFn  func(branch string) error
	lastSHA string
}

func newPoller(cfg *Config, client PlatformClient, scanFn func(string) error) *poller {
	return &poller{cfg: cfg, client: client, scanFn: scanFn}
}

// Run polls the branch on every tick and triggers a scan whenever the HEAD
// SHA changes. It exits cleanly when ctx is cancelled (SIGINT/SIGTERM).
func (p *poller) Run(ctx context.Context) error {
	ui.Printf("  %s Polling branch %s on %s every %s\n",
		color.CyanString("→"),
		color.CyanString(p.cfg.Branch),
		color.CyanString(p.cfg.Repo),
		p.cfg.Interval.String())

	// Check immediately on startup so the user gets feedback right away.
	if err := p.check(); err != nil {
		ui.Printf("  %s Initial poll error: %v\n", color.YellowString("⚠"), err)
	}

	ticker := time.NewTicker(p.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			ui.Printf("\n  %s Polling stopped.\n", color.CyanString("→"))
			return nil
		case <-ticker.C:
			if err := p.check(); err != nil {
				ui.Printf("  %s Poll error: %v\n", color.YellowString("⚠"), err)
			}
		}
	}
}

// check fetches the current HEAD SHA; if it differs from the last seen SHA
// it triggers a scan and updates lastSHA only on success.
func (p *poller) check() error {
	sha, err := p.client.GetBranchSHA(p.cfg.Branch)
	if err != nil {
		return fmt.Errorf("cannot query branch HEAD: %w", err)
	}

	if sha == p.lastSHA {
		ui.Printf("  %s [%s] No changes on %s (%s)\n",
			color.New(color.Faint).Sprint("·"),
			time.Now().Format("15:04:05"),
			p.cfg.Branch,
			sha[:8])
		return nil
	}

	prevLabel := "initial"
	if p.lastSHA != "" {
		prevLabel = p.lastSHA[:8]
	}
	ui.Printf("  %s New commit: %s → %s\n",
		color.CyanString("→"), prevLabel, sha[:8])

	if err := p.scanFn(p.cfg.Branch); err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Update lastSHA only after a successful scan so a transient error
	// does not suppress the re-scan on the next tick.
	p.lastSHA = sha
	return nil
}
