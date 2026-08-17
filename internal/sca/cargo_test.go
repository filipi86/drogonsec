package sca

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The fixture under testdata/cargo was produced by Cargo itself, from the
// Cargo.toml committed beside it:
//
//	docker run --rm rust:1-slim cargo generate-lockfile
//
// It is committed verbatim. Three declared dependencies and one development
// dependency resolve to thirty crates, among them two versions of time and two
// of wasi — the case a name-keyed parser gets wrong and nobody writing a
// fixture by hand would think to produce.
const cargoFixture = "testdata/cargo"

func TestCargoLock(t *testing.T) {
	deps, err := (&CargoLockParser{}).Parse(filepath.Join(cargoFixture, "Cargo.lock"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	t.Run("reports every crate in the tree", func(t *testing.T) {
		if len(deps) != 30 {
			t.Errorf("parsed %d crates, want 30: %v", len(deps), depNames(deps))
		}
	})

	t.Run("the local crate is the project, not a dependency of it", func(t *testing.T) {
		// drogonsec-fixture is the package being scanned. It has no source
		// because it was never fetched, and reporting it would invent a
		// dependency on the code doing the depending.
		if _, ok := findDep(deps, "drogonsec-fixture"); ok {
			t.Error("the root crate was reported as one of its own dependencies")
		}
	})

	t.Run("the root's dependency list is the direct set", func(t *testing.T) {
		// Cargo.lock records the root itself, so unlike composer.lock or
		// yarn.lock it needs no sibling manifest to know what was asked for.
		// Cargo does not separate development dependencies here, and tempfile
		// is one: it is installed, it builds, and a flaw in it is real.
		direct := map[string]bool{
			"chrono":   true,
			"smallvec": true,
			"tempfile": true,
		}
		for _, d := range deps {
			// time appears twice; the declared one is handled below.
			if d.Name == "time" {
				continue
			}
			if d.Direct != direct[d.Name] {
				t.Errorf("%s direct = %v, want %v", d.Name, d.Direct, direct[d.Name])
			}
		}
	})

	t.Run("two versions of one crate are told apart", func(t *testing.T) {
		// This is the whole reason a Cargo node is keyed by name and version.
		// The project declares time 0.3.9; chrono drags in time 0.1.45, which
		// is the copy RUSTSEC-2020-0071 is about. Collapsing them by name would
		// either lose the vulnerable version or call it direct.
		var declared, transitive bool
		for _, d := range deps {
			if d.Name != "time" {
				continue
			}
			switch d.Version {
			case "0.3.9":
				declared = true
				if !d.Direct {
					t.Error("time 0.3.9 is declared by the project and is direct")
				}
			case "0.1.45":
				transitive = true
				if d.Direct {
					t.Error("time 0.1.45 arrived through chrono and is not direct")
				}
				if want := []string{"chrono"}; !reflect.DeepEqual(d.Path, want) {
					t.Errorf("time 0.1.45 route = %v, want %v", d.Path, want)
				}
			default:
				t.Errorf("unexpected time version %q", d.Version)
			}
		}
		if !declared || !transitive {
			t.Errorf("both versions of time must be reported (0.3.9=%v 0.1.45=%v)", declared, transitive)
		}
	})

	t.Run("an unversioned edge resolves when the name is unique", func(t *testing.T) {
		// Cargo writes "libc" rather than "libc 0.2.189" wherever the tree
		// holds only one copy, and writes the version only where it does not.
		d, ok := findDep(deps, "libc")
		if !ok {
			t.Fatal("libc missing: a bare-name edge went unresolved")
		}
		if len(d.Path) == 0 && !d.Direct {
			t.Error("libc was reported with no route, so no edge reached it")
		}
	})

	t.Run("build metadata in a version survives the split", func(t *testing.T) {
		// "wasi 0.10.0+wasi-snapshot-preview1" is one edge, not two, and the
		// two wasi copies are reached from different crates.
		want := map[string][]string{
			"0.10.0+wasi-snapshot-preview1": {"chrono", "time"},
			"0.11.1+wasi-snapshot-preview1": {"tempfile", "rand", "rand_core", "getrandom"},
		}
		found := 0
		for _, d := range deps {
			if d.Name != "wasi" {
				continue
			}
			found++
			if !reflect.DeepEqual(d.Path, want[d.Version]) {
				t.Errorf("wasi %s route = %v, want %v", d.Version, d.Path, want[d.Version])
			}
		}
		if found != 2 {
			t.Errorf("found %d wasi crates, want 2", found)
		}
	})

	t.Run("the route reaches the bottom of a deep tree", func(t *testing.T) {
		d, ok := findDep(deps, "unicode-ident")
		if !ok {
			t.Fatal("unicode-ident missing")
		}
		want := []string{"tempfile", "rand", "rand_chacha", "ppv-lite86", "zerocopy", "zerocopy-derive", "proc-macro2"}
		if !reflect.DeepEqual(d.Path, want) {
			t.Errorf("route = %v, want %v", d.Path, want)
		}
	})

	t.Run("the ecosystem is the one OSV knows", func(t *testing.T) {
		for _, d := range deps {
			if d.Ecosystem != "cargo" {
				t.Errorf("%s ecosystem = %q, want cargo", d.Name, d.Ecosystem)
			}
		}
	})
}

// cargoLockV2 is the older layout, which Cargo wrote until 1.53 and still
// reads. Every edge carries its version and its source, and the checksums live
// in a [metadata] table instead of on the package. The graph it describes is
// the same, so nothing but the descriptor parsing changes.
const cargoLockV2 = `# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
[[package]]
name = "app"
version = "0.1.0"
dependencies = [
 "chrono 0.4.19 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "chrono"
version = "0.4.19"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "time 0.1.45 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "time"
version = "0.1.45"
source = "registry+https://github.com/rust-lang/crates.io-index"

[metadata]
"checksum chrono 0.4.19 (registry+https://github.com/rust-lang/crates.io-index)" = "670ad68c9088"
"checksum time 0.1.45 (registry+https://github.com/rust-lang/crates.io-index)" = "1b797afad3f31"
`

func TestCargoLockV2Descriptors(t *testing.T) {
	dir := writeFiles(t, map[string]string{"Cargo.lock": cargoLockV2})

	deps, err := (&CargoLockParser{}).Parse(filepath.Join(dir, "Cargo.lock"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if got, want := depNames(deps), []string{"chrono", "time"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}

	chrono, _ := findDep(deps, "chrono")
	if !chrono.Direct {
		t.Error("chrono is the root's only dependency and is direct")
	}
	tm, _ := findDep(deps, "time")
	if want := []string{"chrono"}; !reflect.DeepEqual(tm.Path, want) {
		t.Errorf("time route = %v, want %v — the source in parentheses is not part of the version", tm.Path, want)
	}
}

// TestCargoLockRefusesToGuessAnAmbiguousEdge covers the case Cargo promises
// cannot happen. If a bare-name edge ever does point at a name held twice,
// picking one attaches a route through a crate that does not lead there, which
// is worse than reporting the crate with no route at all.
func TestCargoLockRefusesToGuessAnAmbiguousEdge(t *testing.T) {
	dir := writeFiles(t, map[string]string{"Cargo.lock": `
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["dup"]

[[package]]
name = "dup"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "dup"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`})

	deps, err := (&CargoLockParser{}).Parse(filepath.Join(dir, "Cargo.lock"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("parsed %d crates, want both copies of dup", len(deps))
	}
	for _, d := range deps {
		if d.Direct || len(d.Path) != 0 {
			t.Errorf("dup %s was given a route from an edge that names no version", d.Version)
		}
	}
}

func TestCargoLockRejectsMalformedTOML(t *testing.T) {
	dir := writeFiles(t, map[string]string{"Cargo.lock": "[[package]\nname = "})

	if _, err := (&CargoLockParser{}).Parse(filepath.Join(dir, "Cargo.lock")); err == nil {
		t.Error("Parse accepted a truncated lockfile")
	}
}

func TestCargoTOMLParser(t *testing.T) {
	dir := writeFiles(t, map[string]string{"Cargo.toml": `
[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "1.0.130"
tokio = { version = "1.14.0", features = ["full"] }
local = { path = "../local" }
shared = { workspace = true }
forked = { git = "https://example.test/forked" }

[dev-dependencies]
tempfile = "3.2.0"

[build-dependencies]
cc = "^1.0.72"
`})

	deps, err := (&CargoTOMLParser{}).Parse(filepath.Join(dir, "Cargo.toml"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	t.Run("reads all three dependency tables", func(t *testing.T) {
		want := []string{"cc", "serde", "tempfile", "tokio"}
		if got := depNames(deps); !reflect.DeepEqual(got, want) {
			t.Errorf("parsed %v, want %v", got, want)
		}
	})

	t.Run("a version can be written plainly or in a table", func(t *testing.T) {
		for name, want := range map[string]string{
			"serde":    "1.0.130",
			"tokio":    "1.14.0",
			"tempfile": "3.2.0",
			"cc":       "1.0.72",
		} {
			d, ok := findDep(deps, name)
			if !ok {
				t.Fatalf("%s missing", name)
			}
			if d.Version != want {
				t.Errorf("%s version = %q, want %q", name, d.Version, want)
			}
		}
	})

	t.Run("entries with no version of their own are dropped", func(t *testing.T) {
		// A path, git or workspace-inherited dependency carries no version
		// here. Reported at the empty string it would match every advisory for
		// the crate, or none, depending on the database.
		for _, name := range []string{"local", "shared", "forked"} {
			if _, ok := findDep(deps, name); ok {
				t.Errorf("%s has no version in this manifest and cannot be matched against an advisory", name)
			}
		}
	})
}

// TestCargoLockTakesPrecedenceOverManifest pins the tier order for Rust. The
// lockfile names thirty crates at resolved versions; Cargo.toml names four at
// ranges. Counting both reports chrono twice, the second time at a version
// nothing installed.
func TestCargoLockTakesPrecedenceOverManifest(t *testing.T) {
	deps, err := New(cargoFixture).collectDependencies()
	if err != nil {
		t.Fatalf("collectDependencies returned error: %v", err)
	}

	if len(deps) != 30 {
		t.Errorf("collected %d crates, want 30 — the manifest and the lockfile were both counted", len(deps))
	}
	for _, d := range deps {
		if filepath.Base(d.File) != "Cargo.lock" {
			t.Errorf("%s came from %s, but the lockfile covers this directory", d.Name, filepath.Base(d.File))
		}
	}
}

// TestCargoManifestIsTheFallback checks the tier below: with no lockfile, the
// four declared crates are all that can be seen, and the transitive tree is
// gone.
func TestCargoManifestIsTheFallback(t *testing.T) {
	manifest, err := os.ReadFile(filepath.Join(cargoFixture, "Cargo.toml"))
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}
	dir := writeFiles(t, map[string]string{"Cargo.toml": string(manifest)})

	deps, err := New(dir).collectDependencies()
	if err != nil {
		t.Fatalf("collectDependencies returned error: %v", err)
	}

	want := []string{"chrono", "smallvec", "tempfile", "time"}
	if got := depNames(deps); !reflect.DeepEqual(got, want) {
		t.Errorf("parsed %v, want %v", got, want)
	}
	for _, d := range deps {
		if !d.Direct {
			t.Errorf("%s comes from a manifest, which lists only what the project declares", d.Name)
		}
	}
}
