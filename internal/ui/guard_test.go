package ui

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// directPrint matches a write that goes straight to stdout: fmt.Print, Printf
// and Println with no explicit writer.
var directPrint = regexp.MustCompile(`\bfmt\.Print(f|ln)?\(`)

// stdoutIsTheAnswer lists the files whose output IS what the caller asked for,
// and which therefore belong on stdout. Everything else in the codebase is
// narration about a run and has to go through this package.
//
//   - cli/commands.go carries `version` and `rules list`. Their output is the
//     entire answer to the command, so sending it to stderr would make
//     `drogonsec rules list > rules.txt` write an empty file.
var stdoutIsTheAnswer = map[string]string{
	"internal/cli/commands.go": "version and rules list are the command's answer",
}

// TestNarrationDoesNotGoToStdout keeps the separation this package exists to
// enforce.
//
// stdout carries the data a caller asked for: the findings report, the shell
// completion script, the rules listing. Everything else — banner, progress,
// summary, warnings — is narration and belongs on stderr, or it lands in the
// middle of a report and makes `--format json` unparseable. That was the state
// this package was introduced to fix, and a single new fmt.Printf in a scan
// path is enough to break it again, silently, for every consumer at once.
func TestNarrationDoesNotGoToStdout(t *testing.T) {
	root := repoRoot(t)

	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if _, allowed := stdoutIsTheAnswer[rel]; allowed {
			return nil
		}
		// This package defines the alternative, so it is exempt.
		if strings.HasPrefix(rel, "internal/ui/") {
			return nil
		}

		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for i, line := range strings.Split(string(src), "\n") {
			if directPrint.MatchString(line) {
				t.Errorf("%s:%d writes to stdout directly:\n\t%s\n"+
					"Narration belongs on stderr — use ui.Printf/Println/Print. If this "+
					"output really is the answer to a command, add the file to "+
					"stdoutIsTheAnswer with the reason.",
					rel, i+1, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the source tree: %v", err)
	}
}

// TestStdoutAllowlistIsAccurate stops the allowlist from outliving its
// entries: a file listed there that no longer prints to stdout is stale, and a
// stale entry would quietly permit a future regression in that file.
func TestStdoutAllowlistIsAccurate(t *testing.T) {
	root := repoRoot(t)

	for rel, reason := range stdoutIsTheAnswer {
		if reason == "" {
			t.Errorf("%s is allowlisted without a reason", rel)
		}
		src, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Errorf("allowlisted file %s cannot be read: %v", rel, err)
			continue
		}
		if !directPrint.Match(src) {
			t.Errorf("%s is allowlisted but no longer prints to stdout; drop the entry", rel)
		}
	}
}

// repoRoot returns the module root, two levels up from this package.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolving the repository root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("go.mod not found at %s: %v", root, err)
	}
	return root
}

func TestWritersGoToOut(t *testing.T) {
	var buf strings.Builder
	original := Out
	t.Cleanup(func() { Out = original })
	Out = &buf

	Printf("%s=%d\n", "n", 1)
	Println("line")
	Print("bare")

	if got, want := buf.String(), "n=1\nline\nbare"; got != want {
		t.Errorf("captured %q, want %q", got, want)
	}
}
