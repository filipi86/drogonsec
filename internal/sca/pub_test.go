package sca

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The fixture under testdata/pub was produced by the Dart SDK itself, from the
// pubspec.yaml committed beside it:
//
//	PUB_CACHE=$PWD/cache dart pub get
//
// The lockfile is committed verbatim. testdata/pub/cache holds the pubspec.yaml
// of every package pub downloaded, also verbatim, and nothing else — that file
// is all the parser reads from the cache. Two declared dependencies and one
// development dependency resolve to twelve packages.
const pubFixture = "testdata/pub"

func pubFixtureCache(t *testing.T) {
	t.Helper()
	cache, err := filepath.Abs(filepath.Join(pubFixture, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PUB_CACHE", cache)
}

func TestPubspecLock(t *testing.T) {
	pubFixtureCache(t)

	deps, err := (&PubspecLockParser{}).Parse(filepath.Join(pubFixture, "pubspec.lock"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	t.Run("reports every package in the solve", func(t *testing.T) {
		if len(deps) != 12 {
			t.Errorf("parsed %d packages, want 12: %v", len(deps), depNames(deps))
		}
	})

	t.Run("the lockfile's own labels are the direct set", func(t *testing.T) {
		// pubspec.lock is the one lockfile besides Cargo.lock that says what
		// the project declared, so no sibling manifest is consulted.
		direct := map[string]bool{"dio": true, "http": true, "lints": true}
		for _, d := range deps {
			if d.Direct != direct[d.Name] {
				t.Errorf("%s direct = %v, want %v", d.Name, d.Direct, direct[d.Name])
			}
		}
	})

	t.Run("versions are the resolved ones", func(t *testing.T) {
		// The pubspec asks for http ^0.13.5; pub selected 0.13.6. The range
		// is what a manifest-only scan would have had to go on.
		http, _ := findDep(deps, "http")
		if http.Version != "0.13.6" {
			t.Errorf("http version = %q, want the locked 0.13.6", http.Version)
		}
		if http.VersionIsRange {
			t.Error("a locked version is not a range")
		}
	})

	t.Run("routes come from the cached pubspecs", func(t *testing.T) {
		// dio -> http_parser -> string_scanner is the shortest route: the
		// walk is breadth-first and roots are visited in name order, so dio
		// reaches http_parser before http does.
		want := map[string][]string{
			"http_parser":    {"dio"},
			"string_scanner": {"dio", "http_parser"},
			"async":          {"http"},
			"term_glyph":     {"dio", "http_parser", "source_span"},
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

	t.Run("edges reach the SBOM", func(t *testing.T) {
		d, _ := findDep(deps, "http")
		want := []Ref{
			{Name: "async", Version: "2.13.1"},
			{Name: "http_parser", Version: "4.1.2"},
			{Name: "meta", Version: "1.19.0"},
		}
		if !reflect.DeepEqual(d.Requires, want) {
			t.Errorf("http requires %v, want %v", d.Requires, want)
		}
	})
}

// TestPubspecLockWithoutCache covers a lockfile checked out on a machine that
// never ran pub get. Every package is still reported with the direct set
// intact; only the routes, which need the cache, are gone.
func TestPubspecLockWithoutCache(t *testing.T) {
	t.Setenv("PUB_CACHE", t.TempDir())

	deps, err := (&PubspecLockParser{}).Parse(filepath.Join(pubFixture, "pubspec.lock"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(deps) != 12 {
		t.Fatalf("parsed %d packages, want 12", len(deps))
	}
	dio, _ := findDep(deps, "dio")
	if !dio.Direct {
		t.Error("dio is declared and must be direct without a cache")
	}
	for _, d := range deps {
		if len(d.Path) != 0 {
			t.Errorf("%s has route %v with no cache to derive it from", d.Name, d.Path)
		}
	}
}

// TestPubspecLockPackageConfig checks that .dart_tool/package_config.json is
// believed over the default cache location, and that relative rootUris — the
// form pub writes for path dependencies — resolve against .dart_tool itself.
func TestPubspecLockPackageConfig(t *testing.T) {
	t.Setenv("PUB_CACHE", t.TempDir()) // the default location holds nothing

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pubspec.lock"), `packages:
  shared:
    dependency: "direct main"
    description:
      path: "packages/shared"
      relative: true
    source: path
    version: "0.0.1"
  meta:
    dependency: transitive
    description:
      name: meta
      url: "https://pub.dev"
    source: hosted
    version: "1.19.0"
  args:
    dependency: transitive
    description:
      name: args
      url: "https://pub.dev"
    source: hosted
    version: "2.5.0"
  flutter:
    dependency: "direct main"
    description: flutter
    source: sdk
    version: "0.0.0"
`)
	writeFile(t, filepath.Join(dir, "packages", "shared", "pubspec.yaml"), "name: shared\ndependencies:\n  meta: ^1.0.0\n")
	writeFile(t, filepath.Join(dir, "elsewhere", "meta", "pubspec.yaml"), "name: meta\ndependencies:\n  args: ^2.0.0\n")
	writeFile(t, filepath.Join(dir, ".dart_tool", "package_config.json"), `{
  "configVersion": 2,
  "packages": [
    {"name": "meta", "rootUri": "../elsewhere/meta"},
    {"name": "shared", "rootUri": "../packages/shared"}
  ]
}`)

	deps, err := (&PubspecLockParser{}).Parse(filepath.Join(dir, "pubspec.lock"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	// The path package is the project's own code and the SDK is Flutter
	// itself: neither is a registry package to report.
	if got := depNames(deps); !equalStrings(got, []string{"args", "meta"}) {
		t.Fatalf("parsed %v, want [args meta]", got)
	}
	meta, _ := findDep(deps, "meta")
	if !meta.Direct {
		t.Error("meta is required by a path package of the project, so it is direct")
	}
	args, _ := findDep(deps, "args")
	if !reflect.DeepEqual(args.Path, []string{"meta"}) {
		t.Errorf("args route = %v, want [meta] — the package_config location was not read", args.Path)
	}
}

// TestPubspecLockTakesOverFromPubspec runs the engine over the fixture: the
// lockfile is read and the pubspec.yaml beside it, which holds a range, is not
// reported a second time.
func TestPubspecLockTakesOverFromPubspec(t *testing.T) {
	pubFixtureCache(t)

	deps, err := New(pubFixture).collectDependencies()
	if err != nil {
		t.Fatalf("collectDependencies returned error: %v", err)
	}
	// testdata/pub/cache holds pubspec.yaml files of its own, which are
	// packages in pub's cache rather than projects; scope to the fixture root.
	root := filepath.Clean(pubFixture)
	var count int
	for _, d := range deps {
		if filepath.Dir(d.File) != root {
			continue
		}
		count++
		if filepath.Base(d.File) != "pubspec.lock" {
			t.Errorf("%s attributed to %s, want pubspec.lock", d.Name, d.File)
		}
	}
	if count != 12 {
		t.Errorf("found %d dependencies for the fixture, want 12", count)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
