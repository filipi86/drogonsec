package sca

import (
	"path/filepath"
	"reflect"
	"testing"
)

// The fixture under testdata/gomod was produced by the Go toolchain itself:
// a main package importing gin v1.7.0 and BurntSushi/toml v1.2.0, then
//
//	GOMODCACHE=$PWD/modcache go mod tidy
//
// go.mod is committed verbatim. testdata/gomod/modcache holds, verbatim, the
// cached go.mod of each of the sixteen modules go.mod selects, at the path the
// toolchain stores it — cache/download/<module>/@v/<version>.mod — and nothing
// else, since that file is all the parser reads from the cache. Every edge the
// parser derives from it was checked against `go mod graph` on the same module.
const goModFixture = "testdata/gomod"

func goModFixtureCache(t *testing.T) {
	t.Helper()
	cache, err := filepath.Abs(filepath.Join(goModFixture, "modcache"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOMODCACHE", cache)
}

func TestGoModFullSet(t *testing.T) {
	goModFixtureCache(t)

	deps, err := (&GoModParser{}).Parse(filepath.Join(goModFixture, "go.mod"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	t.Run("reports every module go.mod selects", func(t *testing.T) {
		if len(deps) != 16 {
			t.Errorf("parsed %d modules, want 16: %v", len(deps), depNames(deps))
		}
	})

	t.Run("an indirect requirement is not direct", func(t *testing.T) {
		// The manifest path marked everything in go.mod direct, including the
		// fourteen modules `go mod tidy` itself labels "// indirect".
		direct := map[string]bool{"github.com/gin-gonic/gin": true, "github.com/BurntSushi/toml": true}
		for _, d := range deps {
			if d.Direct != direct[d.Name] {
				t.Errorf("%s direct = %v, want %v", d.Name, d.Direct, direct[d.Name])
			}
		}
	})

	t.Run("routes come from the cached go.mod files", func(t *testing.T) {
		want := map[string][]string{
			"github.com/go-playground/validator/v10": {"github.com/gin-gonic/gin"},
			"golang.org/x/crypto":                    {"github.com/gin-gonic/gin", "github.com/go-playground/validator/v10"},
			"golang.org/x/sys":                       {"github.com/gin-gonic/gin", "github.com/mattn/go-isatty"},
		}
		for name, route := range want {
			d, ok := findDep(deps, name)
			if !ok {
				t.Errorf("%s missing", name)
				continue
			}
			if !reflect.DeepEqual(d.Path, route) {
				t.Errorf("%s route = %v, want %v", name, d.Path, route)
			}
		}
	})

	t.Run("edges resolve to the selected version", func(t *testing.T) {
		// validator v10.4.1 requires golang.org/x/crypto at a 2020-06-22
		// pseudo-version; the edge lands on whatever go.mod selected, which is
		// what minimal version selection builds.
		d, _ := findDep(deps, "github.com/go-playground/validator/v10")
		var crypto *Ref
		for i, r := range d.Requires {
			if r.Name == "golang.org/x/crypto" {
				crypto = &d.Requires[i]
			}
		}
		if crypto == nil || crypto.Version != "v0.0.0-20200622213623-75b288015ac9" {
			t.Errorf("validator's edge to x/crypto = %v, want the selected pseudo-version", crypto)
		}
	})

	t.Run("a module outside go.mod is not added", func(t *testing.T) {
		// gin's go.mod requires stretchr/testify for its own tests. Graph
		// pruning keeps it out of this build, and go.mod does not list it.
		if _, ok := findDep(deps, "github.com/stretchr/testify"); ok {
			t.Error("testify was reported, but it is not part of the build")
		}
	})
}

// TestGoModWithoutCache covers a go.mod scanned on a machine with no module
// cache: the full set and the direct split survive, and only routes are lost.
func TestGoModWithoutCache(t *testing.T) {
	t.Setenv("GOMODCACHE", t.TempDir())

	deps, err := (&GoModParser{}).Parse(filepath.Join(goModFixture, "go.mod"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(deps) != 16 {
		t.Fatalf("parsed %d modules, want 16", len(deps))
	}
	for _, d := range deps {
		if len(d.Path) != 0 {
			t.Errorf("%s has route %v with no cache to derive it from", d.Name, d.Path)
		}
	}
}

func TestGoModReplace(t *testing.T) {
	t.Setenv("GOMODCACHE", t.TempDir())

	path := writeManifest(t, "go.mod", `module example.com/app

go 1.22

require (
	github.com/pkg/errors v0.9.1
	github.com/old/lib v1.0.0 // indirect
	example.com/local v0.0.0
	github.com/pinned/only v1.2.0
)

replace github.com/old/lib => github.com/fork/lib v1.0.5

replace (
	example.com/local => ../local
	github.com/pinned/only v1.1.0 => github.com/other/only v9.9.9
)
`)
	deps, err := (&GoModParser{}).Parse(path)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	// The fork is what is built, so it is what an advisory is matched
	// against. The directory replacement is the project's own code. The
	// version-scoped replacement names a version that is not selected, so it
	// does not apply.
	want := []string{"github.com/fork/lib", "github.com/pinned/only", "github.com/pkg/errors"}
	if got := depNames(deps); !equalStrings(got, want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
	fork, _ := findDep(deps, "github.com/fork/lib")
	if fork.Version != "v1.0.5" || fork.Direct {
		t.Errorf("fork = %s direct=%v, want v1.0.5 indirect", fork.Version, fork.Direct)
	}
}

func TestEscapeModulePath(t *testing.T) {
	if got := escapeModulePath("github.com/BurntSushi/toml"); got != "github.com/!burnt!sushi/toml" {
		t.Errorf("escapeModulePath = %q", got)
	}
}

// TestQueryBatchSendsGoVersionsWithoutPrefix pins the one place Go's spelling
// of a version and OSV's disagree: v1.7.0 in go.mod, 1.7.0 in the database.
func TestQueryBatchSendsGoVersionsWithoutPrefix(t *testing.T) {
	client, captured := newTestOSVClient(t, emptyResults)

	deps := []Dependency{
		{Name: "github.com/gin-gonic/gin", Version: "v1.7.0", Ecosystem: "go"},
		{Name: "vue", Version: "2.6.0", Ecosystem: "npm"},
	}
	if _, err := client.QueryBatch(deps); err != nil {
		t.Fatalf("QueryBatch returned error: %v", err)
	}
	if got := captured.Queries[0].Version; got != "1.7.0" {
		t.Errorf("Go query version = %q, want %q", got, "1.7.0")
	}
	if got := captured.Queries[1].Version; got != "2.6.0" {
		t.Errorf("npm query version = %q, want it untouched", got)
	}
}

func TestOsvVulnToFindingWritesGoFixesWithPrefix(t *testing.T) {
	vuln := osvVuln{
		ID: "GO-2023-1737",
		Affected: []osvAffected{{Ranges: []osvRange{{Events: []osvEvent{
			{Introduced: "0"}, {Fixed: "1.9.0"},
		}}}}},
	}
	f := osvVulnToFinding(vuln, Dependency{Name: "github.com/gin-gonic/gin", Version: "v1.7.0", Ecosystem: "go"})
	if f.FixedVersion != "v1.9.0" {
		t.Errorf("FixedVersion = %q, want %q", f.FixedVersion, "v1.9.0")
	}
	if f.PackageVersion != "v1.7.0" {
		t.Errorf("PackageVersion = %q, want the go.mod spelling", f.PackageVersion)
	}
}

// TestCacheLookupsStayInsideTheCache pins the check that keeps a hostile
// manifest from turning a cache lookup into a read anywhere on disk. The
// scanner reads only dependency names from what it finds, but a name is still
// not a path.
func TestCacheLookupsStayInsideTheCache(t *testing.T) {
	for _, path := range []string{"../../etc", "github.com/a/../../b", `github.com\a`, "/abs", ""} {
		if safeModulePath(path) {
			t.Errorf("safeModulePath(%q) = true", path)
		}
	}
	if !safeModulePath("github.com/go-playground/validator/v10") {
		t.Error("a real module path was rejected")
	}
	for _, c := range [][3]string{{"..", "a", "1"}, {"org", "../x", "1"}, {"org", "a", "../1"}, {"org", "a", "${v}"}} {
		if safeMavenCoordinates(c[0], c[1], c[2]) {
			t.Errorf("safeMavenCoordinates(%v) = true", c)
		}
	}
	if !safeMavenCoordinates("org.apache.logging.log4j", "log4j-core", "2.14.1") {
		t.Error("real coordinates were rejected")
	}
	if pubPackageName.MatchString("../../etc") {
		t.Error("a traversal was accepted as a pub package name")
	}
}
