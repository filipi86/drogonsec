package leaks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/filipi86/drogonsec/internal/config"
)

// writeFile creates a file with the given content in a fresh temporary
// directory and returns its path.
func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

// A syntactically valid AWS access key ID, used as a stand-in for a real
// secret. It is not a credential: the pattern is public and the value is not
// bound to any account.
const fakeAWSKey = "AKIAIOSFODNN7EXAMPLE"

func TestScanFileReportsLocation(t *testing.T) {
	path := writeFile(t, "config.yml", strings.Join([]string{
		"service: api",
		"",
		"aws_access_key_id: " + fakeAWSKey,
	}, "\n"))

	findings, err := NewDetector().ScanFile(path)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("no findings, want the AWS key to be reported")
	}

	f := findings[0]
	if f.File != path {
		t.Errorf("File = %q, want %q", f.File, path)
	}
	// Lines are 1-based, and the key sits on the third line.
	if f.Line != 3 {
		t.Errorf("Line = %d, want 3", f.Line)
	}
	if strings.Contains(f.Match, "OSFODNN7EXAMPLE") {
		t.Errorf("Match = %q still contains the secret; findings must be redacted", f.Match)
	}
}

// TestScanFileSkipsBinaryContent guards the null-byte path: a binary file that
// happens to contain something resembling a key must not be scanned as text.
func TestScanFileSkipsBinaryContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blob.bin")
	content := append([]byte("aws_access_key_id: "+fakeAWSKey+"\n"), 0x00, 0x01, 0x02)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("writing binary file: %v", err)
	}

	findings, err := NewDetector().ScanFile(path)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings in binary content, want 0", len(findings))
	}
}

func TestScanFileMissingFile(t *testing.T) {
	_, err := NewDetector().ScanFile(filepath.Join(t.TempDir(), "absent.txt"))
	if err == nil {
		t.Error("ScanFile succeeded on a missing file, want an error")
	}
}

// TestScanFileSkipsOverlongLines covers the ReDoS guard. A minified bundle is
// one enormous line; feeding it to every pattern is what the cap prevents.
func TestScanFileSkipsOverlongLines(t *testing.T) {
	long := strings.Repeat("a", maxLineLength+1) + " aws_access_key_id: " + fakeAWSKey
	path := writeFile(t, "bundle.min.js", long)

	findings, err := NewDetector().ScanFile(path)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings on an over-long line, want 0 (the ReDoS guard)", len(findings))
	}
}

// TestScanLineAgreesWithScanFile is the regression test for the divergence the
// matcher extraction removed: ScanLine used to skip the entropy gate that the
// file scanner applied, so a test could pass on input a real scan discards.
func TestScanLineAgreesWithScanFile(t *testing.T) {
	lines := []string{
		"aws_access_key_id: " + fakeAWSKey,
		`api_key = "your-api-key-here"`,
		"# aws_access_key_id: " + fakeAWSKey,
		"nothing to see here",
		`password = "aaaaaaaaaaaaaaaaaaaa"`,
	}

	d := NewDetector()
	for _, line := range lines {
		t.Run(line, func(t *testing.T) {
			path := writeFile(t, "sample.txt", line)
			fromFile, err := d.ScanFile(path)
			if err != nil {
				t.Fatalf("ScanFile returned error: %v", err)
			}
			fromLine := d.ScanLine(line)

			if len(fromFile) != len(fromLine) {
				t.Fatalf("ScanFile reported %d findings, ScanLine %d — the two "+
					"paths disagree about what counts as a leak", len(fromFile), len(fromLine))
			}
			for i := range fromFile {
				if fromFile[i].RuleID != fromLine[i].RuleID {
					t.Errorf("finding %d: ScanFile rule %q, ScanLine rule %q",
						i, fromFile[i].RuleID, fromLine[i].RuleID)
				}
			}
		})
	}
}

// TestMatchLineAppliesTheEntropyGate pins the placeholder-suppression
// behaviour: generic rules only fire above the entropy threshold, so
// documentation samples do not become findings.
func TestMatchLineAppliesTheEntropyGate(t *testing.T) {
	d := NewDetector()

	for _, f := range d.matchLine(`generic_secret = "aaaaaaaaaaaaaaaaaaaaaaaa"`) {
		if f.Entropy > 0 && f.Entropy < minGenericEntropy {
			t.Errorf("rule %q reported a match with entropy %.2f, below the %.1f gate",
				f.RuleID, f.Entropy, minGenericEntropy)
		}
	}
}

func TestMatchLineIgnoresEmptyLines(t *testing.T) {
	d := NewDetector()

	for _, line := range []string{"", "   ", "\t", "\t  \t"} {
		if got := d.matchLine(line); len(got) != 0 {
			t.Errorf("matchLine(%q) returned %d findings, want 0", line, len(got))
		}
	}
}

// TestMatchLineReportsCommentedOutSecrets is the case a leading-"#" skip used
// to hide. Commenting a credential out is what people do instead of rotating
// it, and the value stays in the working tree and in the history either way —
// so it is reported at the rule's own severity, not a reduced one.
func TestMatchLineReportsCommentedOutSecrets(t *testing.T) {
	d := NewDetector()

	tests := []struct {
		name string
		line string
	}{
		{"shell or env comment", "# aws_access_key_id = " + fakeAWSKey},
		{"indented comment", "    # aws_access_key_id = " + fakeAWSKey},
		{"yaml comment after a key", "aws_access_key_id: " + fakeAWSKey + " # old value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.matchLine(tt.line)
			if len(findings) == 0 {
				t.Fatalf("matchLine(%q) reported nothing; a commented-out "+
					"credential is still committed", tt.line)
			}

			var found bool
			for _, f := range findings {
				if f.RuleID == "LEAK-001" {
					found = true
					if f.Severity != awsKeyRuleSeverity(t, d) {
						t.Errorf("Severity = %v, want the rule's own severity %v — "+
							"a commented secret is not a lesser one",
							f.Severity, awsKeyRuleSeverity(t, d))
					}
				}
			}
			if !found {
				t.Errorf("LEAK-001 did not fire on %q", tt.line)
			}
		})
	}
}

// awsKeyRuleSeverity reads the configured severity of the AWS key rule so the
// assertion above tracks the rule instead of hardcoding a level.
func awsKeyRuleSeverity(t *testing.T, d *Detector) config.Severity {
	t.Helper()
	for _, r := range d.rules {
		if r.ID == "LEAK-001" {
			return r.Severity
		}
	}
	t.Fatal("rule LEAK-001 not found")
	return ""
}

func TestRedactSecret(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{
			// Short secrets are masked whole: revealing 3 of 12 characters
			// still narrows an offline search meaningfully.
			name: "short secret is fully masked",
			in:   "hunter2hunter",
			want: "***REDACTED***",
		},
		{
			name: "empty string",
			in:   "",
			want: "***REDACTED***",
		},
		{
			name: "20 characters keeps a 3-character prefix",
			in:   "AKIAIOSFODNN7EXAMPLE",
			want: "AKI*****************",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactSecret(tt.in)
			if got != tt.want {
				t.Errorf("redactSecret(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if len(tt.in) >= 20 && len(got) != len(tt.in) {
				t.Errorf("redaction changed the length: %d vs %d", len(got), len(tt.in))
			}
		})
	}
}

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name string
		in   string
		min  float64
		max  float64
	}{
		{"empty", "", 0, 0},
		{"single repeated character carries no information", "aaaaaaaa", 0, 0},
		{"two symbols evenly split", "abab", 0.99, 1.01},
		{"four symbols evenly split", "abcd", 1.99, 2.01},
		{"a real-looking key is high entropy", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", 4.0, 6.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shannonEntropy(tt.in)
			if got < tt.min || got > tt.max {
				t.Errorf("shannonEntropy(%q) = %.4f, want between %.2f and %.2f",
					tt.in, got, tt.min, tt.max)
			}
		})
	}
}

func TestIsBinary(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want bool
	}{
		{"empty is not binary", nil, false},
		{"plain ascii", []byte("hello world\n"), false},
		{"utf-8 accented text", []byte("configuração da aplicação\n"), false},
		{"tabs and newlines are text", []byte("a\tb\r\nc\n"), false},
		{"a null byte marks it binary", []byte("text\x00more"), true},
		{"mostly control bytes", []byte{0x01, 0x02, 0x03, 0x04, 0x05, 'a', 'b'}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isBinary(tt.in); got != tt.want {
				t.Errorf("isBinary(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestShouldSkip(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"logo.png", true},
		{"IMAGE.PNG", true}, // the extension check is case-insensitive
		{"archive.zip", true},
		{"app.jar", true},
		{"package-lock.json", false},
		{"Gemfile.lock", true},
		{"config.yml", false},
		{"main.go", false},
		{"src/deep/path/photo.JPEG", true},
		{"noextension", false},
	}

	for _, tt := range tests {
		if got := shouldSkip(tt.path); got != tt.want {
			t.Errorf("shouldSkip(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestGetFileExtensionIgnoreListIsNormalized(t *testing.T) {
	seen := make(map[string]bool)
	for _, ext := range GetFileExtensionIgnoreList() {
		if !strings.HasPrefix(ext, ".") {
			t.Errorf("extension %q does not start with a dot", ext)
		}
		if ext != strings.ToLower(ext) {
			t.Errorf("extension %q is not lowercase; the lookup lowercases before comparing", ext)
		}
		if seen[ext] {
			t.Errorf("extension %q is listed twice", ext)
		}
		seen[ext] = true
	}
}

func TestDetectorRulesAreWellFormed(t *testing.T) {
	d := NewDetector()
	if len(d.rules) == 0 {
		t.Fatal("no rules were loaded")
	}

	ids := make(map[string]bool, len(d.rules))
	for _, r := range d.rules {
		if r.ID == "" {
			t.Errorf("rule %q has no ID", r.Name)
		}
		if ids[r.ID] {
			t.Errorf("rule ID %q is used more than once; findings would be ambiguous", r.ID)
		}
		ids[r.ID] = true

		if r.Name == "" {
			t.Errorf("rule %s has no name", r.ID)
		}
		if r.Description == "" {
			t.Errorf("rule %s has no description", r.ID)
		}
		if r.Pattern == nil {
			t.Errorf("rule %s has a nil pattern", r.ID)
			continue
		}
		// mustCompile swallows a bad pattern and substitutes one that can
		// never match, which would silently disable the rule.
		if r.Pattern.String() == `[^\s\S]` {
			t.Errorf("rule %s has an unparseable pattern and can never match", r.ID)
		}
		if r.Severity == "" {
			t.Errorf("rule %s has no severity", r.ID)
		}
	}
}

// TestMustCompileFallsBackToANeverMatchingPattern documents what happens to an
// invalid pattern: the rule is disabled rather than crashing the scanner.
func TestMustCompileFallsBackToANeverMatchingPattern(t *testing.T) {
	re := mustCompile("([unclosed")
	if re == nil {
		t.Fatal("mustCompile returned nil")
	}
	if re.MatchString("anything at all") {
		t.Error("the fallback pattern matched; it must never match")
	}
}
