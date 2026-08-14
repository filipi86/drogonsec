package sca

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/filipi86/drogonsec/internal/config"
)

// writeFiles creates a set of files in one fresh temporary directory, keyed by
// relative name, and returns the directory. Lockfile parsing depends on what
// sits next to the lockfile, so the fixtures need more than a single file.
func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("creating directory for %s: %v", name, err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	return dir
}

// lockV3 is an npm 7+ lockfile. express is the only declared dependency;
// everything else is hoisted alongside it, which is exactly the layout that
// makes "which of these did I ask for" impossible to answer from the key alone.
const lockV3 = `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "app",
      "dependencies": { "express": "^4.17.1" },
      "devDependencies": { "jest": "^29.0.0" }
    },
    "node_modules/express": {
      "version": "4.17.1",
      "dependencies": { "cookie": "0.4.0", "qs": "6.7.0" }
    },
    "node_modules/cookie": { "version": "0.4.0" },
    "node_modules/qs": {
      "version": "6.7.0",
      "dependencies": { "side-channel": "1.0.4" }
    },
    "node_modules/side-channel": { "version": "1.0.4" },
    "node_modules/jest": { "version": "29.7.0" },
    "node_modules/@scope/util": { "version": "2.1.0" },
    "node_modules/orphan": { "version": "9.9.9" },
    "node_modules/app-workspace": { "resolved": "packages/app", "link": true },
    "node_modules/no-version": { "resolved": "https://example.test/x.tgz" }
  }
}`

func TestPackageLockV3(t *testing.T) {
	dir := writeFiles(t, map[string]string{"package-lock.json": lockV3})

	deps, err := (&PackageLockParser{}).Parse(filepath.Join(dir, "package-lock.json"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	t.Run("reports every installed package, not only the declared ones", func(t *testing.T) {
		want := []string{"@scope/util", "cookie", "express", "jest", "orphan", "qs", "side-channel"}
		if got := depNames(deps); !reflect.DeepEqual(got, want) {
			t.Errorf("parsed %v, want %v", got, want)
		}
	})

	t.Run("only what the project declares is direct", func(t *testing.T) {
		for _, name := range []string{"express", "jest"} {
			d, ok := findDep(deps, name)
			if !ok {
				t.Fatalf("%s missing", name)
			}
			if !d.Direct {
				t.Errorf("%s should be direct: the root entry declares it", name)
			}
		}
		// A hoisted transitive package sits at the same depth in node_modules
		// as a declared one. Calling it direct would tell a reader to upgrade a
		// package their project never names.
		for _, name := range []string{"cookie", "qs", "side-channel"} {
			d, _ := findDep(deps, name)
			if d.Direct {
				t.Errorf("%s is hoisted, not declared, and must not be direct", name)
			}
		}
	})

	t.Run("the route records how a package was introduced", func(t *testing.T) {
		tests := []struct {
			name string
			want []string
		}{
			{"express", nil},
			{"cookie", []string{"express"}},
			{"qs", []string{"express"}},
			{"side-channel", []string{"express", "qs"}},
		}
		for _, tt := range tests {
			d, ok := findDep(deps, tt.name)
			if !ok {
				t.Fatalf("%s missing", tt.name)
			}
			if !reflect.DeepEqual(d.Path, tt.want) {
				t.Errorf("%s route = %v, want %v", tt.name, d.Path, tt.want)
			}
		}
	})

	t.Run("resolved versions, never ranges", func(t *testing.T) {
		// The root entry asks for "^4.17.1". Matching that against an advisory
		// is meaningless: it is not a version that exists.
		d, _ := findDep(deps, "express")
		if d.Version != "4.17.1" {
			t.Errorf("express version = %q, want the resolved 4.17.1", d.Version)
		}
	})

	t.Run("scoped names survive the path split", func(t *testing.T) {
		if _, ok := findDep(deps, "@scope/util"); !ok {
			t.Error(`@scope/util was lost: the "/" inside a scope is not a path separator`)
		}
	})

	t.Run("unreachable packages are still reported", func(t *testing.T) {
		// A lockfile keeps entries for platforms the current install skipped.
		// A vulnerability in one of those is not made harmless by the edge
		// being absent from this file, so it is reported with no route.
		d, ok := findDep(deps, "orphan")
		if !ok {
			t.Fatal("orphan was dropped; an unreachable package is still installed code")
		}
		if d.Direct || len(d.Path) != 0 {
			t.Errorf("orphan should carry no route, got direct=%v path=%v", d.Direct, d.Path)
		}
	})

	t.Run("workspace links and versionless entries are skipped", func(t *testing.T) {
		for _, name := range []string{"app-workspace", "no-version"} {
			if _, ok := findDep(deps, name); ok {
				t.Errorf("%s has no published version to match an advisory against", name)
			}
		}
	})
}

// TestPackageLockNestedShadowing covers the case the whole resolution rule
// exists for: two versions of one package in the same tree. Node resolves from
// the dependent's own node_modules outwards, so the nested copy is what the
// parent actually loads — and reporting the hoisted version against it would
// name a version that code never runs.
func TestPackageLockNestedShadowing(t *testing.T) {
	dir := writeFiles(t, map[string]string{"package-lock.json": `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": { "dependencies": { "alpha": "1.0.0", "beta": "1.0.0" } },
	    "node_modules/alpha": { "version": "1.0.0", "dependencies": { "ms": "2.0.0" } },
	    "node_modules/alpha/node_modules/ms": { "version": "2.0.0" },
	    "node_modules/beta": { "version": "1.0.0", "dependencies": { "ms": "2.1.3" } },
	    "node_modules/ms": { "version": "2.1.3" }
	  }
	}`})

	deps, err := (&PackageLockParser{}).Parse(filepath.Join(dir, "package-lock.json"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	var versions []string
	for _, d := range deps {
		if d.Name == "ms" {
			versions = append(versions, d.Version)
		}
	}
	if len(versions) != 2 {
		t.Fatalf("got ms %v, want both installed copies (2.0.0 and 2.1.3)", versions)
	}

	for _, d := range deps {
		if d.Name != "ms" {
			continue
		}
		switch d.Version {
		case "2.0.0":
			if !reflect.DeepEqual(d.Path, []string{"alpha"}) {
				t.Errorf("nested ms 2.0.0 route = %v, want [alpha]", d.Path)
			}
		case "2.1.3":
			if len(d.Path) != 1 || (d.Path[0] != "beta" && d.Path[0] != "alpha") {
				t.Errorf("hoisted ms 2.1.3 route = %v, want a single-hop route", d.Path)
			}
		}
	}
}

// TestPackageLockV1 covers npm 6, whose lockfile nests the tree and never
// records what the project declared.
func TestPackageLockV1(t *testing.T) {
	lock := `{
	  "lockfileVersion": 1,
	  "dependencies": {
	    "express": {
	      "version": "4.17.1",
	      "requires": { "cookie": "0.4.0" }
	    },
	    "cookie": { "version": "0.4.0" },
	    "nested-parent": {
	      "version": "1.0.0",
	      "requires": { "shared": "1.0.0" },
	      "dependencies": {
	        "shared": { "version": "1.0.0" }
	      }
	    }
	  }
	}`

	t.Run("the sibling package.json supplies what the lockfile omits", func(t *testing.T) {
		dir := writeFiles(t, map[string]string{
			"package-lock.json": lock,
			"package.json":      `{"dependencies": {"express": "^4.17.1", "nested-parent": "^1.0.0"}}`,
		})

		deps, err := (&PackageLockParser{}).Parse(filepath.Join(dir, "package-lock.json"))
		if err != nil {
			t.Fatalf("Parse returned error: %v", err)
		}

		if d, _ := findDep(deps, "express"); !d.Direct {
			t.Error("express is declared in package.json and should be direct")
		}
		if d, _ := findDep(deps, "cookie"); d.Direct {
			t.Error("cookie is required by express, not declared")
		}
		if d, _ := findDep(deps, "cookie"); !reflect.DeepEqual(d.Path, []string{"express"}) {
			t.Errorf("cookie route = %v, want [express]", d.Path)
		}
		if d, _ := findDep(deps, "shared"); !reflect.DeepEqual(d.Path, []string{"nested-parent"}) {
			t.Errorf("nested shared route = %v, want [nested-parent]", d.Path)
		}
	})

	t.Run("without a package.json every package is still reported", func(t *testing.T) {
		dir := writeFiles(t, map[string]string{"package-lock.json": lock})

		deps, err := (&PackageLockParser{}).Parse(filepath.Join(dir, "package-lock.json"))
		if err != nil {
			t.Fatalf("Parse returned error: %v", err)
		}

		// Losing the direct/transitive split is acceptable; losing the packages
		// would mean reporting nothing for a repository that vendors its
		// lockfile without its manifest.
		want := []string{"cookie", "express", "nested-parent", "shared"}
		if got := depNames(deps); !reflect.DeepEqual(got, want) {
			t.Errorf("parsed %v, want %v", got, want)
		}
		for _, d := range deps {
			if d.Direct {
				t.Errorf("%s cannot be known to be direct with no package.json", d.Name)
			}
		}
	})
}

// TestLockfileTakesPrecedenceOverManifest pins the rule that keeps the two npm
// parsers from double-counting. Without it every declared dependency is
// reported twice: once at its resolved version and once at the range the
// manifest asked for, and the range matches no advisory.
func TestLockfileTakesPrecedenceOverManifest(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"package-lock.json":      lockV3,
		"package.json":           `{"dependencies": {"express": "^4.17.1"}}`,
		"other/package.json":     `{"dependencies": {"lodash": "4.17.15"}}`,
		"other/requirements.txt": "flask==2.0.0\n",
	})

	deps, err := New(dir).collectDependencies()
	if err != nil {
		t.Fatalf("collectDependencies returned error: %v", err)
	}

	var expressCount int
	for _, d := range deps {
		if d.Name == "express" {
			expressCount++
			if d.Version != "4.17.1" {
				t.Errorf("express version = %q, want the lockfile's resolved 4.17.1", d.Version)
			}
		}
	}
	if expressCount != 1 {
		t.Errorf("express reported %d times, want once — the manifest copy should be dropped", expressCount)
	}

	// A directory the lockfile does not cover keeps its manifest, and so does
	// an unrelated ecosystem: precedence is per directory and per ecosystem,
	// not global.
	if d, ok := findDep(deps, "lodash"); !ok || !d.Direct {
		t.Error("a package.json in a directory with no lockfile must still be parsed")
	}
	if _, ok := findDep(deps, "flask"); !ok {
		t.Error("a different ecosystem must not be suppressed by an npm lockfile")
	}
}

// TestPackageLockIsDeterministic guards against Go's randomised map iteration
// reaching the output. A route that changes between runs of an unchanged scan
// makes every diff between two reports untrustworthy.
func TestPackageLockIsDeterministic(t *testing.T) {
	dir := writeFiles(t, map[string]string{"package-lock.json": lockV3})
	path := filepath.Join(dir, "package-lock.json")

	first, err := (&PackageLockParser{}).Parse(path)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	for i := 0; i < 8; i++ {
		again, err := (&PackageLockParser{}).Parse(path)
		if err != nil {
			t.Fatalf("Parse returned error: %v", err)
		}
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("run %d differs from the first:\n%+v\n%+v", i+1, first, again)
		}
	}
}

// TestDedupeFindings covers OSV holding one flaw under several identifiers that
// alias each other. path-to-regexp 0.1.7 really does come back as both
// GHSA-37ch-88jc-xwx2 and GHSA-9wv6-86v2-598j, each listing the other, and both
// resolving to CVE-2024-45296.
func TestDedupeFindings(t *testing.T) {
	finding := func(pkg, version, cve, advisory, manifest string) Finding {
		return Finding{
			PackageName:    pkg,
			PackageVersion: version,
			Ecosystem:      "npm",
			ManifestFile:   manifest,
			CVE:            cve,
			Advisory:       advisory,
			Severity:       config.SeverityHigh,
		}
	}

	tests := []struct {
		name string
		in   []Finding
		want int
	}{
		{
			name: "the same CVE under two advisory ids is one vulnerability",
			in: []Finding{
				finding("path-to-regexp", "0.1.7", "CVE-2024-45296", "https://osv.dev/vulnerability/GHSA-37ch-88jc-xwx2", "a/package-lock.json"),
				finding("path-to-regexp", "0.1.7", "CVE-2024-45296", "https://osv.dev/vulnerability/GHSA-9wv6-86v2-598j", "a/package-lock.json"),
			},
			want: 1,
		},
		{
			name: "different CVEs in one package are different vulnerabilities",
			in: []Finding{
				finding("path-to-regexp", "0.1.7", "CVE-2024-45296", "x", "a/package-lock.json"),
				finding("path-to-regexp", "0.1.7", "CVE-2024-52798", "y", "a/package-lock.json"),
			},
			want: 2,
		},
		{
			name: "advisories with no CVE are kept apart by their own id",
			in: []Finding{
				finding("left-pad", "1.0.0", "", "https://osv.dev/vulnerability/GHSA-aaaa", "a/package-lock.json"),
				finding("left-pad", "1.0.0", "", "https://osv.dev/vulnerability/GHSA-bbbb", "a/package-lock.json"),
			},
			want: 2,
		},
		{
			name: "the same package vulnerable in two projects is reported for each",
			in: []Finding{
				finding("qs", "6.7.0", "CVE-2022-24999", "x", "api/package-lock.json"),
				finding("qs", "6.7.0", "CVE-2022-24999", "x", "web/package-lock.json"),
			},
			want: 2,
		},
		{
			name: "two versions of one package are two findings",
			in: []Finding{
				finding("ms", "2.0.0", "CVE-2017-16113", "x", "a/package-lock.json"),
				finding("ms", "2.1.3", "CVE-2017-16113", "x", "a/package-lock.json"),
			},
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dedupeFindings(tt.in); len(got) != tt.want {
				var ids []string
				for _, f := range got {
					ids = append(ids, f.PackageName+"@"+f.PackageVersion+" "+f.CVE)
				}
				t.Errorf("kept %d findings (%s), want %d", len(got), strings.Join(ids, ", "), tt.want)
			}
		})
	}
}
