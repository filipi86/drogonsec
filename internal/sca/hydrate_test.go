package sca

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/filipi86/drogonsec/internal/config"
)

// osvStub serves both OSV endpoints the client uses: the batch query, which
// answers with identifiers only exactly as the real API does, and the
// per-advisory detail endpoint.
type osvStub struct {
	// vulnIDs are returned, in order, one list per query in the batch.
	vulnIDs [][]string
	// details are served by the detail endpoint, keyed by advisory ID. An ID
	// that is absent produces a 404, standing in for a fetch failure.
	details map[string]osvVuln

	mu    sync.Mutex
	calls map[string]int
}

func (s *osvStub) detailCalls(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[id]
}

func newOSVStub(t *testing.T, stub *osvStub) *osvClient {
	t.Helper()
	stub.calls = make(map[string]int)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		results := make([]osvQueryResult, len(stub.vulnIDs))
		for i, ids := range stub.vulnIDs {
			for _, id := range ids {
				// The real batch endpoint returns {id, modified} and nothing
				// more — no summary, no severity, no affected ranges.
				results[i].Vulns = append(results[i].Vulns, osvVuln{ID: id})
			}
		}
		_ = json.NewEncoder(w).Encode(osvBatchResponse{Results: results})
	})
	mux.HandleFunc("/v1/vulns/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")

		stub.mu.Lock()
		stub.calls[id]++
		stub.mu.Unlock()

		v, ok := stub.details[id]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(v)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &osvClient{
		http:    srv.Client(),
		baseURL: srv.URL + "/v1/querybatch",
		vulnURL: srv.URL + "/v1/vulns/",
	}
}

// TestQueryBatchHydratesAdvisoryDetails is the reason hydration exists. The
// batch endpoint answers with identifiers only, so without a second request
// every finding would carry the OSV ID as its "CVE", no description, no CVSS
// and — most damaging — no fixed version, leaving the user with a count of
// vulnerabilities and no way to act on them.
func TestQueryBatchHydratesAdvisoryDetails(t *testing.T) {
	client := newOSVStub(t, &osvStub{
		vulnIDs: [][]string{{"PYSEC-2022-190"}},
		details: map[string]osvVuln{
			"PYSEC-2022-190": {
				ID:      "PYSEC-2022-190",
				Aliases: []string{"CVE-2022-28346", "GHSA-2gwj-7jmv-h26r"},
				Details: "SQL injection in QuerySet.annotate()",
				Severity: []osvSeverity{
					{Type: "CVSS_V3", Score: "9.8"},
				},
				Affected: []osvAffected{{
					Ranges: []osvRange{{
						Type:   "ECOSYSTEM",
						Events: []osvEvent{{Introduced: "0"}, {Fixed: "3.2.13"}},
					}},
				}},
			},
		},
	})

	findings, err := client.QueryBatch([]Dependency{
		{Name: "django", Version: "3.2.12", Ecosystem: "pypi", File: "requirements.txt"},
	})
	if err != nil {
		t.Fatalf("QueryBatch returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.CVE != "CVE-2022-28346" {
		t.Errorf("CVE = %q, want the alias %q from the full record", f.CVE, "CVE-2022-28346")
	}
	if f.FixedVersion != "3.2.13" {
		t.Errorf("FixedVersion = %q, want %q — without it the finding carries no "+
			"upgrade target", f.FixedVersion, "3.2.13")
	}
	if f.CVSS != 9.8 {
		t.Errorf("CVSS = %v, want 9.8", f.CVSS)
	}
	if f.Severity != config.SeverityCritical {
		t.Errorf("Severity = %v, want CRITICAL for CVSS 9.8 rather than the "+
			"unscored default", f.Severity)
	}
	if f.Description == "" {
		t.Error("Description is empty; the advisory text was not carried over")
	}
}

// TestQueryBatchFetchesEachAdvisoryOnce keeps a shared advisory from costing
// one request per affected package.
func TestQueryBatchFetchesEachAdvisoryOnce(t *testing.T) {
	stub := &osvStub{
		// The same advisory affects both dependencies.
		vulnIDs: [][]string{{"GHSA-shared"}, {"GHSA-shared"}},
		details: map[string]osvVuln{
			"GHSA-shared": {ID: "GHSA-shared", Details: "shared advisory"},
		},
	}
	client := newOSVStub(t, stub)

	findings, err := client.QueryBatch([]Dependency{
		{Name: "pkg-a", Version: "1.0.0", Ecosystem: "npm"},
		{Name: "pkg-b", Version: "2.0.0", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("QueryBatch returned error: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (one per affected package)", len(findings))
	}
	if got := stub.detailCalls("GHSA-shared"); got != 1 {
		t.Errorf("the advisory was fetched %d times, want 1", got)
	}
	// Both findings must still carry the detail.
	for _, f := range findings {
		if f.Description != "shared advisory" {
			t.Errorf("finding for %s has description %q, want the shared advisory text",
				f.PackageName, f.Description)
		}
	}
}

// TestQueryBatchKeepsFindingsWhenHydrationFails is the degradation path: an
// advisory we cannot describe is still one worth reporting, so a failed detail
// fetch must not drop the finding.
func TestQueryBatchKeepsFindingsWhenHydrationFails(t *testing.T) {
	client := newOSVStub(t, &osvStub{
		vulnIDs: [][]string{{"GHSA-missing"}},
		details: map[string]osvVuln{}, // every detail request 404s
	})

	findings, err := client.QueryBatch([]Dependency{
		{Name: "lodash", Version: "4.17.15", Ecosystem: "npm", File: "package.json"},
	})
	if err != nil {
		t.Fatalf("QueryBatch returned error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 — a vulnerability that could not be "+
			"described is still a vulnerability", len(findings))
	}
	f := findings[0]
	if f.CVE != "GHSA-missing" {
		t.Errorf("CVE = %q, want the OSV identifier as a fallback", f.CVE)
	}
	if f.PackageName != "lodash" {
		t.Errorf("PackageName = %q, want %q", f.PackageName, "lodash")
	}
	// With no score available the finding must not be quietly downgraded.
	if f.Severity != config.SeverityHigh {
		t.Errorf("Severity = %v, want HIGH for an unscored advisory", f.Severity)
	}
}

func TestHydrateDeduplicatesAndIgnoresEmptyIDs(t *testing.T) {
	stub := &osvStub{
		details: map[string]osvVuln{
			"A": {ID: "A", Details: "a"},
			"B": {ID: "B", Details: "b"},
		},
	}
	client := newOSVStub(t, stub)

	got := client.hydrate([]string{"A", "B", "A", "", "B", "A"})

	if len(got) != 2 {
		t.Fatalf("hydrate returned %d records, want 2", len(got))
	}
	for _, id := range []string{"A", "B"} {
		if n := stub.detailCalls(id); n != 1 {
			t.Errorf("advisory %s was fetched %d times, want 1", id, n)
		}
	}
}

func TestHydrateEmptyInput(t *testing.T) {
	client := newOSVStub(t, &osvStub{details: map[string]osvVuln{}})

	if got := client.hydrate(nil); len(got) != 0 {
		t.Errorf("hydrate(nil) returned %d records, want 0", len(got))
	}
	if got := client.hydrate([]string{"", ""}); len(got) != 0 {
		t.Errorf("hydrate of empty ids returned %d records, want 0", len(got))
	}
}

// TestHydrateHandlesMoreAdvisoriesThanWorkers exercises the worker pool past
// its bound; a real Django pin produces dozens of advisories at once.
func TestHydrateHandlesMoreAdvisoriesThanWorkers(t *testing.T) {
	details := make(map[string]osvVuln, osvHydrateWorkers*3)
	ids := make([]string, 0, osvHydrateWorkers*3)
	for i := 0; i < osvHydrateWorkers*3; i++ {
		id := "GHSA-" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		details[id] = osvVuln{ID: id, Details: "advisory " + id}
		ids = append(ids, id)
	}

	client := newOSVStub(t, &osvStub{details: details})

	got := client.hydrate(ids)

	if len(got) != len(details) {
		t.Errorf("hydrate returned %d records, want %d", len(got), len(details))
	}
	for id := range details {
		if got[id].ID != id {
			t.Errorf("advisory %s is missing from the result", id)
		}
	}
}

func TestFetchVulnRejectsAMalformedRecord(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id": `))
	}))
	defer srv.Close()

	client := &osvClient{http: srv.Client(), baseURL: srv.URL, vulnURL: srv.URL + "/"}
	if _, err := client.fetchVuln("GHSA-x"); err == nil {
		t.Error("fetchVuln accepted a truncated JSON record, want an error")
	}
}
