package reporter

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/filipi86/drogonsec/internal/analyzer"
)

func TestPurlFor(t *testing.T) {
	cases := []struct {
		eco, name, version, want string
	}{
		{"npm", "lodash", "4.17.15", "pkg:npm/lodash@4.17.15"},
		{"npm", "@angular/core", "17.0.0", "pkg:npm/%40angular/core@17.0.0"},
		{"go", "github.com/go-git/go-git/v5", "v5.19.1", "pkg:golang/github.com/go-git/go-git/v5@v5.19.1"},
		{"pypi", "requests", "2.31.0", "pkg:pypi/requests@2.31.0"},
		{"rubygems", "rails", "7.1.0", "pkg:gem/rails@7.1.0"},
		{"packagist", "monolog/monolog", "2.9.1", "pkg:composer/monolog/monolog@2.9.1"},
		{"maven", "struts2-core", "2.3.34", "pkg:maven/struts2-core@2.3.34"},
		{"pub", "http", "1.2.0", "pkg:pub/http@1.2.0"},
		{"npm", "noversion", "", "pkg:npm/noversion"},
	}
	for _, c := range cases {
		got := purlFor(c.eco, c.name, c.version)
		if got != c.want {
			t.Errorf("purlFor(%q,%q,%q) = %q; want %q", c.eco, c.name, c.version, got, c.want)
		}
	}
}

func TestBuildCycloneDX_DedupAndSort(t *testing.T) {
	result := &analyzer.ScanResult{
		TargetPath: "/tmp/myproject",
		ScanTime:   time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC),
		Version:    "0.1.0",
		Dependencies: []analyzer.Dependency{
			{Name: "lodash", Version: "4.17.15", Ecosystem: "npm", Manifest: "a/package.json"},
			{Name: "lodash", Version: "4.17.15", Ecosystem: "npm", Manifest: "b/package.json"}, // dup
			{Name: "express", Version: "4.18.2", Ecosystem: "npm", Manifest: "a/package.json"},
		},
	}

	bom := buildCycloneDX(result)

	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.5" || bom.Version != 1 {
		t.Fatalf("unexpected BOM header: %+v", bom)
	}
	if len(bom.Components) != 2 {
		t.Fatalf("expected 2 deduped components, got %d", len(bom.Components))
	}
	// Sorted by bom-ref: express before lodash.
	if bom.Components[0].Name != "express" || bom.Components[1].Name != "lodash" {
		t.Errorf("components not sorted by purl: %q, %q", bom.Components[0].Name, bom.Components[1].Name)
	}
	if bom.Components[0].PURL != "pkg:npm/express@4.18.2" {
		t.Errorf("unexpected purl: %q", bom.Components[0].PURL)
	}
	if bom.Metadata.Component == nil || bom.Metadata.Component.Name != "myproject" {
		t.Errorf("expected metadata.component name 'myproject', got %+v", bom.Metadata.Component)
	}
	if bom.Metadata.Timestamp != "2026-06-23T12:00:00Z" {
		t.Errorf("unexpected timestamp: %q", bom.Metadata.Timestamp)
	}
}

func TestCycloneDXReporter_WriteValidJSON(t *testing.T) {
	result := &analyzer.ScanResult{
		TargetPath: "/tmp/proj",
		ScanTime:   time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC),
		Version:    "0.1.0",
		Dependencies: []analyzer.Dependency{
			{Name: "requests", Version: "2.31.0", Ecosystem: "pypi", Manifest: "requirements.txt"},
		},
	}

	var buf bytes.Buffer
	if err := (&CycloneDXReporter{}).Write(result, &buf); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if parsed["bomFormat"] != "CycloneDX" {
		t.Errorf("missing/invalid bomFormat: %v", parsed["bomFormat"])
	}
	sn, ok := parsed["serialNumber"].(string)
	if !ok || len(sn) < len("urn:uuid:") || sn[:9] != "urn:uuid:" {
		t.Errorf("expected urn:uuid serialNumber, got %v", parsed["serialNumber"])
	}
}

func TestNewReporter_CycloneDX(t *testing.T) {
	rep, err := New("cyclonedx")
	if err != nil {
		t.Fatalf("New(cyclonedx) error: %v", err)
	}
	if _, ok := rep.(*CycloneDXReporter); !ok {
		t.Errorf("expected *CycloneDXReporter, got %T", rep)
	}
}
