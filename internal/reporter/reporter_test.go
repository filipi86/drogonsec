package reporter

import "testing"

func TestSarifStartLine(t *testing.T) {
	cases := []struct {
		in, want int
	}{
		{0, 1},  // SARIF requires startLine >= 1; unknown becomes 1
		{-5, 1}, // defensive: negatives clamped
		{1, 1},
		{42, 42},
	}
	for _, tc := range cases {
		if got := sarifStartLine(tc.in); got != tc.want {
			t.Errorf("sarifStartLine(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestSarifStartColumn(t *testing.T) {
	cases := []struct {
		in, want int
	}{
		{0, 0},  // unknown → omitted via omitempty
		{-3, 0}, // negative → omitted (no fabricated column)
		{1, 1},
		{17, 17},
	}
	for _, tc := range cases {
		if got := sarifStartColumn(tc.in); got != tc.want {
			t.Errorf("sarifStartColumn(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestSafeURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"https passes through", "https://osv.dev/vulnerability/GHSA-xxxx", "https://osv.dev/vulnerability/GHSA-xxxx"},
		{"http passes through", "http://example.com/advisory", "http://example.com/advisory"},
		{"javascript scheme blocked", "javascript:alert(1)", "#"},
		{"data scheme blocked", "data:text/html,<script>alert(1)</script>", "#"},
		{"vbscript scheme blocked", "vbscript:msgbox(1)", "#"},
		{"file scheme blocked", "file:///etc/passwd", "#"},
		{"mixed case javascript blocked", "JaVaScRiPt:alert(1)", "#"},
		{"whitespace trimmed around javascript blocked", "  javascript:alert(1)  ", "#"},
		{"empty returns hash", "", "#"},
		{"relative url blocked (no scheme)", "/path/only", "#"},
		{"protocol-relative blocked", "//evil.com/x", "#"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := safeURL(tc.in)
			if got != tc.want {
				t.Fatalf("safeURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
