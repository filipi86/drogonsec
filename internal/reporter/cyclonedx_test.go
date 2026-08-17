package reporter

import (
	"bytes"
	"encoding/json"
	"reflect"
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
		{"cargo", "time", "0.1.45", "pkg:cargo/time@0.1.45"},
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

// TestBuildCycloneDX_DependencyGraph covers the section that turns a component
// list into a bill of materials: which component pulled in which.
//
// The tree it describes is express → cookie → side-channel, with side-channel
// also required directly by express — the shape that shows why the graph is
// built from every edge rather than from one route per component.
func TestBuildCycloneDX_DependencyGraph(t *testing.T) {
	result := &analyzer.ScanResult{
		TargetPath: "/tmp/myproject",
		ScanTime:   time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC),
		Dependencies: []analyzer.Dependency{
			{Name: "express", Version: "4.18.2", Ecosystem: "npm", Manifest: "package-lock.json", Direct: true,
				Requires: []analyzer.DependencyRef{{Name: "cookie", Version: "0.5.0"}, {Name: "side-channel", Version: "1.0.4"}}},
			{Name: "cookie", Version: "0.5.0", Ecosystem: "npm", Manifest: "package-lock.json",
				Requires: []analyzer.DependencyRef{{Name: "side-channel", Version: "1.0.4"}}},
			{Name: "side-channel", Version: "1.0.4", Ecosystem: "npm", Manifest: "package-lock.json"},
			// A second manifest contributing the same package with a further
			// edge: the two entries are unioned, not overwritten.
			{Name: "express", Version: "4.18.2", Ecosystem: "npm", Manifest: "api/package-lock.json", Direct: true,
				Requires: []analyzer.DependencyRef{{Name: "cookie", Version: "0.5.0"}, {Name: "unlisted", Version: "9.9.9"}}},
		},
	}

	bom := buildCycloneDX(result)

	graph := make(map[string][]string, len(bom.Dependencies))
	for _, d := range bom.Dependencies {
		graph[d.Ref] = d.DependsOn
	}

	t.Run("the root depends on what the project declares", func(t *testing.T) {
		want := []string{"pkg:npm/express@4.18.2"}
		if got := graph["root:myproject"]; !reflect.DeepEqual(got, want) {
			t.Errorf("root dependsOn = %v, want %v", got, want)
		}
	})

	t.Run("every edge is kept, not one route per component", func(t *testing.T) {
		// side-channel is reachable through cookie and straight from express.
		// A graph built from the shortest route would record only the second,
		// and a consumer asking "what pulls this in" would get half an answer.
		want := []string{"pkg:npm/cookie@0.5.0", "pkg:npm/side-channel@1.0.4"}
		if got := graph["pkg:npm/express@4.18.2"]; !reflect.DeepEqual(got, want) {
			t.Errorf("express dependsOn = %v, want %v", got, want)
		}
		if got := graph["pkg:npm/cookie@0.5.0"]; !reflect.DeepEqual(got, []string{"pkg:npm/side-channel@1.0.4"}) {
			t.Errorf("cookie dependsOn = %v", got)
		}
	})

	t.Run("a leaf is listed with no dependencies rather than left out", func(t *testing.T) {
		// In CycloneDX an empty dependsOn asserts the component has no
		// dependencies; omitting the node asserts nothing at all.
		got, ok := graph["pkg:npm/side-channel@1.0.4"]
		if !ok {
			t.Fatal("the leaf component has no node in the graph")
		}
		if len(got) != 0 {
			t.Errorf("leaf dependsOn = %v, want empty", got)
		}
	})

	t.Run("edges to components outside the BOM are dropped", func(t *testing.T) {
		// "unlisted" is required but never resolved into the inventory, so it
		// is not a component. A dependsOn naming it would make the BOM invalid.
		for ref, children := range graph {
			for _, child := range children {
				if child == "pkg:npm/unlisted@9.9.9" {
					t.Errorf("%s points at a component that is not in the document", ref)
				}
			}
		}
	})

	t.Run("every component has a node", func(t *testing.T) {
		for _, c := range bom.Components {
			if _, ok := graph[c.BOMRef]; !ok {
				t.Errorf("%s is a component with no entry in the dependency graph", c.BOMRef)
			}
		}
		// Each component, plus the root.
		if len(bom.Dependencies) != len(bom.Components)+1 {
			t.Errorf("graph has %d nodes for %d components", len(bom.Dependencies), len(bom.Components))
		}
	})
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
