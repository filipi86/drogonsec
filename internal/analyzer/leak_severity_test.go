package analyzer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/filipi86/drogonsec/internal/config"
)

// leakTree writes a target directory holding one secret that stays at its rule
// severity and one that the test-path demotion lowers to LOW.
func leakTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	// CRITICAL: an AWS key in ordinary configuration.
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"),
		[]byte("aws_access_key_id: AKIAIOSFODNN7EXAMPLE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Demoted to LOW: the same key in a test file, where it is a fixture.
	if err := os.WriteFile(filepath.Join(dir, "creds_test.go"),
		[]byte("const key = \"AKIAIOSFODNN7EXAMPLE\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func leakConfig(dir, minSeverity string) *config.ScanConfig {
	return &config.ScanConfig{
		TargetPath:  dir,
		EnableLeaks: true,
		MinSeverity: minSeverity,
		MaxWorkers:  1,
	}
}

// TestLeakFindingsRespectMinSeverity is the guarantee the leak engine was
// missing: SAST and SCA both dropped findings below --severity while leaks
// reported everything, so the demotions above were decorative — a fixture
// lowered to LOW still reached a report asking for HIGH, and the scan of this
// repository's own test files filled the GitHub Security tab with them.
func TestLeakFindingsRespectMinSeverity(t *testing.T) {
	dir := leakTree(t)

	tests := []struct {
		minSeverity string
		wantFiles   []string
	}{
		{"LOW", []string{"config.yaml", "creds_test.go"}},
		{"MEDIUM", []string{"config.yaml"}},
		{"HIGH", []string{"config.yaml"}},
		{"CRITICAL", []string{"config.yaml"}},
	}

	for _, tt := range tests {
		t.Run(tt.minSeverity, func(t *testing.T) {
			result, err := New(leakConfig(dir, tt.minSeverity)).Run()
			if err != nil {
				t.Fatalf("Run returned error: %v", err)
			}

			got := map[string]bool{}
			for _, f := range result.LeakFindings {
				got[filepath.Base(f.File)] = true
			}

			for _, want := range tt.wantFiles {
				if !got[want] {
					t.Errorf("--severity %s dropped the finding in %s", tt.minSeverity, want)
				}
				delete(got, want)
			}
			for extra := range got {
				t.Errorf("--severity %s reported %s, which is below the floor",
					tt.minSeverity, extra)
			}
		})
	}
}

// TestGitignoredSecretsStayVisibleByDefault pins the resolution of Issue #17:
// a secret on an ignored file is demoted so it stops inflating the CRITICAL
// count, but it is still reported, because a copy committed earlier in history
// is a real exposure. Demoting it to INFO would now hide it altogether — the
// shipped default floor is LOW.
func TestGitignoredSecretsStayVisibleByDefault(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("*.env\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "local.env"),
		[]byte("AWS_SECRET=AKIAIOSFODNN7EXAMPLE\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := New(leakConfig(dir, "LOW")).Run()
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	var found bool
	for _, f := range result.LeakFindings {
		if filepath.Base(f.File) != "local.env" {
			continue
		}
		found = true
		if f.Severity != config.SeverityLow {
			t.Errorf("gitignored secret has severity %s, want LOW: anything lower "+
				"falls below the default floor and disappears from the report",
				f.Severity)
		}
	}
	if !found {
		t.Error("the secret on the gitignored file was not reported at all")
	}
}
