package sca

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/filipi86/drogonsec/internal/config"
)

// newTestOSVClient returns a client pointed at a stub server that records the
// request body it received and replies with the supplied response.
func newTestOSVClient(t *testing.T, respond func(req osvBatchRequest) osvBatchResponse) (*osvClient, *osvBatchRequest) {
	t.Helper()

	var captured osvBatchRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading request body: %v", err)
			return
		}
		if err := json.Unmarshal(body, &captured); err != nil {
			t.Errorf("decoding request body: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(respond(captured)); err != nil {
			t.Errorf("encoding response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	return &osvClient{http: srv.Client(), baseURL: srv.URL}, &captured
}

// emptyResults replies with one empty result per query, which is what OSV
// returns when nothing is known about any of the dependencies.
func emptyResults(req osvBatchRequest) osvBatchResponse {
	return osvBatchResponse{Results: make([]osvQueryResult, len(req.Queries))}
}

// TestQueryBatchQueriesEveryParserEcosystem guards the seam between the
// manifest parsers and the OSV client: every ecosystem string a parser can
// emit must be one the client knows how to translate. A mismatch is silent —
// the dependency is skipped and the scan reports no vulnerabilities for an
// entire language, which is the worst possible failure for a scanner.
func TestQueryBatchQueriesEveryParserEcosystem(t *testing.T) {
	// The ecosystem each parser attaches to the dependencies it produces,
	// and the name OSV knows it by.
	tests := []struct {
		parserEcosystem string
		wantOSV         string
	}{
		{"npm", "npm"},
		{"pypi", "PyPI"},
		{"rubygems", "RubyGems"},
		{"go", "Go"},
		{"maven", "Maven"},
		{"packagist", "Packagist"},
		{"pub", "Pub"},
	}

	for _, tt := range tests {
		t.Run(tt.parserEcosystem, func(t *testing.T) {
			client, captured := newTestOSVClient(t, emptyResults)

			deps := []Dependency{{Name: "somepkg", Version: "1.0.0", Ecosystem: tt.parserEcosystem}}
			if _, err := client.QueryBatch(deps); err != nil {
				t.Fatalf("QueryBatch returned error: %v", err)
			}

			if len(captured.Queries) != 1 {
				t.Fatalf("ecosystem %q was not sent to OSV: got %d queries, want 1 — "+
					"dependencies of this ecosystem are silently never checked",
					tt.parserEcosystem, len(captured.Queries))
			}
			if got := captured.Queries[0].Package.Ecosystem; got != tt.wantOSV {
				t.Errorf("OSV ecosystem = %q, want %q", got, tt.wantOSV)
			}
		})
	}
}

// TestQueryBatchAttributesFindingsToTheRightDependency covers the mapping of
// OSV results back onto dependencies. Dependencies with an ecosystem OSV does
// not cover are dropped from the request, so the Nth result corresponds to the
// Nth *query*, not the Nth dependency. Getting this wrong reports a real CVE
// against a package that does not have it.
func TestQueryBatchAttributesFindingsToTheRightDependency(t *testing.T) {
	deps := []Dependency{
		// Skipped: no OSV ecosystem covers it, so it produces no query.
		{Name: "vendored-thing", Version: "1.0.0", Ecosystem: "unknown-ecosystem"},
		{Name: "lodash", Version: "4.17.15", Ecosystem: "npm"},
	}

	client, captured := newTestOSVClient(t, func(req osvBatchRequest) osvBatchResponse {
		results := make([]osvQueryResult, len(req.Queries))
		// Report a vulnerability for every query the server received. Only
		// lodash is queryable, so only lodash may be reported.
		for i := range results {
			results[i] = osvQueryResult{Vulns: []osvVuln{{
				ID:      "GHSA-test",
				Summary: "test advisory",
			}}}
		}
		return results2response(results)
	})

	findings, err := client.QueryBatch(deps)
	if err != nil {
		t.Fatalf("QueryBatch returned error: %v", err)
	}

	if len(captured.Queries) != 1 {
		t.Fatalf("got %d queries, want 1 (only the npm dependency is queryable)", len(captured.Queries))
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].PackageName != "lodash" {
		t.Errorf("finding attributed to %q, want %q — the vulnerability was "+
			"mapped onto the wrong dependency", findings[0].PackageName, "lodash")
	}
}

func results2response(results []osvQueryResult) osvBatchResponse {
	return osvBatchResponse{Results: results}
}

// TestQueryBatchSkipsUnknownEcosystemsWithoutCallingOSV verifies that a scan
// with nothing queryable makes no request at all rather than sending an empty
// batch.
func TestQueryBatchSkipsUnknownEcosystemsWithoutCallingOSV(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	client := &osvClient{http: srv.Client(), baseURL: srv.URL}
	findings, err := client.QueryBatch([]Dependency{
		{Name: "x", Version: "1.0.0", Ecosystem: "not-a-real-ecosystem"},
	})
	if err != nil {
		t.Fatalf("QueryBatch returned error: %v", err)
	}
	if called {
		t.Error("OSV was called for a batch with no queryable dependencies")
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestQueryBatchEmptyInput(t *testing.T) {
	client := &osvClient{http: http.DefaultClient, baseURL: "http://127.0.0.1:0"}
	findings, err := client.QueryBatch(nil)
	if err != nil {
		t.Fatalf("QueryBatch(nil) returned error: %v", err)
	}
	if findings != nil {
		t.Errorf("QueryBatch(nil) = %v, want nil", findings)
	}
}

func TestQueryBatchPropagatesServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	client := &osvClient{http: srv.Client(), baseURL: srv.URL}
	_, err := client.QueryBatch([]Dependency{{Name: "lodash", Version: "1.0.0", Ecosystem: "npm"}})
	if err == nil {
		t.Fatal("QueryBatch succeeded on a 429 response, want an error so the " +
			"caller can fall back to the local database")
	}
}

func TestOsvVulnToFindingPrefersCVEAlias(t *testing.T) {
	dep := Dependency{Name: "lodash", Version: "4.17.15", Ecosystem: "npm", File: "package.json"}
	vuln := osvVuln{
		ID:      "GHSA-jf85-cpcp-j695",
		Aliases: []string{"SNYK-JS-LODASH-567746", "CVE-2019-10744"},
		Summary: "Prototype pollution",
		Severity: []osvSeverity{
			{Type: "CVSS_V3", Score: "9.1"},
		},
		Affected: []osvAffected{{
			Ranges: []osvRange{{
				Type:   "SEMVER",
				Events: []osvEvent{{Introduced: "0"}, {Fixed: "4.17.12"}},
			}},
		}},
	}

	got := osvVulnToFinding(vuln, dep)

	if got.CVE != "CVE-2019-10744" {
		t.Errorf("CVE = %q, want the CVE alias %q", got.CVE, "CVE-2019-10744")
	}
	if got.FixedVersion != "4.17.12" {
		t.Errorf("FixedVersion = %q, want %q", got.FixedVersion, "4.17.12")
	}
	if got.Severity != config.SeverityCritical {
		t.Errorf("Severity = %v, want CRITICAL for CVSS 9.1", got.Severity)
	}
	// The advisory link must point at the OSV ID, not the CVE alias: that is
	// the identifier osv.dev actually resolves.
	if got.Advisory != "https://osv.dev/vulnerability/GHSA-jf85-cpcp-j695" {
		t.Errorf("Advisory = %q, want it to reference the OSV ID", got.Advisory)
	}
}

func TestOsvVulnToFindingFallsBackToTruncatedDetails(t *testing.T) {
	long := make([]byte, 300)
	for i := range long {
		long[i] = 'a'
	}

	got := osvVulnToFinding(osvVuln{ID: "OSV-1", Details: string(long)}, Dependency{Name: "p"})

	if len(got.Description) != 203 { // 200 characters plus the "..." marker
		t.Errorf("Description length = %d, want 203 (200 + \"...\")", len(got.Description))
	}
}

func TestCvssToSeverity(t *testing.T) {
	tests := []struct {
		score float64
		want  config.Severity
	}{
		{10.0, config.SeverityCritical},
		{9.0, config.SeverityCritical},
		{8.9, config.SeverityHigh},
		{7.0, config.SeverityHigh},
		{6.9, config.SeverityMedium},
		{4.0, config.SeverityMedium},
		{3.9, config.SeverityLow},
		{0.1, config.SeverityLow},
		// An unknown score must not be quietly downgraded: a vulnerability
		// with no CVSS attached is still a vulnerability.
		{0, config.SeverityHigh},
	}

	for _, tt := range tests {
		if got := cvssToSeverity(tt.score); got != tt.want {
			t.Errorf("cvssToSeverity(%v) = %v, want %v", tt.score, got, tt.want)
		}
	}
}

func TestParseCVSSScore(t *testing.T) {
	tests := []struct {
		name  string
		score string
		want  float64
	}{
		{"plain numeric score", "9.8", 9.8},
		{"network attack, low complexity, no privileges", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.0},
		{"network attack only", "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", 7.5},
		{"local attack vector", "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 5.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseCVSSScore(tt.score); got != tt.want {
				t.Errorf("parseCVSSScore(%q) = %v, want %v", tt.score, got, tt.want)
			}
		})
	}
}

func TestParseCVSSDefaultsToHighWithoutAScore(t *testing.T) {
	sev, score := parseCVSS(nil)
	if sev != config.SeverityHigh {
		t.Errorf("severity = %v, want HIGH when OSV supplies no score", sev)
	}
	if score != 0 {
		t.Errorf("score = %v, want 0", score)
	}
}

func TestExtractFixedVersion(t *testing.T) {
	// ranges builds an advisory whose affected entries list the given fixes,
	// one range each, the way OSV reports a patch per release branch.
	ranges := func(fixes ...string) []osvAffected {
		var affected []osvAffected
		for _, f := range fixes {
			affected = append(affected, osvAffected{Ranges: []osvRange{{
				Events: []osvEvent{{Introduced: "0"}, {Fixed: f}},
			}}})
		}
		return affected
	}

	tests := []struct {
		name     string
		fixes    []string
		current  string
		want     string
		wantWhy  string
		affected []osvAffected
	}{
		{
			name:    "single fix",
			fixes:   []string{"1.2.3"},
			current: "1.0.0",
			want:    "1.2.3",
		},
		{
			// CVE-2022-28346 patched 2.2.28, 3.2.13 and 4.0.4. A project on
			// 3.2.12 must be sent to 3.2.13, not back to the 2.2 branch.
			name:    "picks the fix on the branch the project is on",
			fixes:   []string{"4.0.4", "3.2.13", "2.2.28"},
			current: "3.2.12",
			want:    "3.2.13",
			wantWhy: "the lowest fix that is still an upgrade",
		},
		{
			name:    "order in the advisory does not matter",
			fixes:   []string{"2.2.28", "4.0.4", "3.2.13"},
			current: "3.2.12",
			want:    "3.2.13",
		},
		{
			name:    "next branch when the current one has no fix",
			fixes:   []string{"4.0.4", "2.2.28"},
			current: "3.2.12",
			want:    "4.0.4",
		},
		{
			name:    "falls back to the lowest fix when none is an upgrade",
			fixes:   []string{"2.2.28", "3.2.13"},
			current: "4.0.0",
			want:    "2.2.28",
			wantWhy: "an imperfect target beats none",
		},
		{
			name:    "handles a v prefix",
			fixes:   []string{"v1.3.0", "v1.2.0"},
			current: "v1.1.0",
			want:    "v1.2.0",
		},
		{
			name:    "ignores a pre-release suffix when ordering",
			fixes:   []string{"1.3.0-rc1", "1.2.0"},
			current: "1.1.0",
			want:    "1.2.0",
		},
		{
			name:    "unequal segment counts",
			fixes:   []string{"1.2", "1.10.1"},
			current: "1.1",
			want:    "1.2",
		},
		{
			name:    "compares segments numerically, not lexically",
			fixes:   []string{"1.10.0", "1.9.0"},
			current: "1.8.0",
			want:    "1.9.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractFixedVersion(ranges(tt.fixes...), tt.current)
			if got != tt.want {
				msg := ""
				if tt.wantWhy != "" {
					msg = " (" + tt.wantWhy + ")"
				}
				t.Errorf("extractFixedVersion(%v, %q) = %q, want %q%s",
					tt.fixes, tt.current, got, tt.want, msg)
			}
		})
	}

	t.Run("empty when the advisory has no fix", func(t *testing.T) {
		affected := []osvAffected{{Ranges: []osvRange{{
			Events: []osvEvent{{Introduced: "1.0.0"}, {LastAffected: "2.0.0"}},
		}}}}
		if got := extractFixedVersion(affected, "1.5.0"); got != "" {
			t.Errorf("extractFixedVersion() = %q, want empty", got)
		}
	})

	t.Run("empty for an advisory with no affected entries", func(t *testing.T) {
		if got := extractFixedVersion(nil, "1.0.0"); got != "" {
			t.Errorf("extractFixedVersion(nil) = %q, want empty", got)
		}
	})
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.0.1", -1},
		{"1.10.0", "1.9.0", 1}, // numeric, not lexical
		{"2.0.0", "1.99.99", 1},
		{"1.2", "1.2.0", 0}, // missing segments are zero
		{"1.2.1", "1.2", 1}, // ...but a present one still counts
		{"v1.0.0", "1.0.0", 0},
		{"1.0.0-rc1", "1.0.0", 0}, // the suffix is ignored
		{"", "", 0},
		{"1.0.0", "", 1},
		{"", "1.0.0", -1},
		{"1.0.0", "1.0.x", -1}, // a non-numeric segment compares lexically
	}

	for _, tt := range tests {
		if got := compareVersions(tt.a, tt.b); got != tt.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}
