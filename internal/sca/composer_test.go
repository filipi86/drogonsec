package sca

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The fixtures under testdata/composer were produced by Composer 2 itself, from
// the composer.json committed beside them:
//
//	docker run --rm composer:2 install --ignore-platform-reqs --no-scripts
//
// Only the fields no parser reads — dist hashes, autoload maps, author blocks —
// were stripped afterwards, and guzzlehttp/guzzle was left whole so the tests
// keep exercising a real entry's worth of noise. Regenerate them the same way
// rather than editing them by hand: every quirk worth testing here, from the
// "v" that Symfony tags its releases with to the platform requirements mixed
// into every require block, is something the tool does and nobody would think
// to invent.
//
// The project declares three packages and installs twenty.
const composerFixture = "testdata/composer"

// composerAllPackages is the full installed set, as both composer.lock and
// installed.json record it.
var composerAllPackages = []string{
	"guzzlehttp/guzzle",
	"guzzlehttp/promises",
	"guzzlehttp/psr7",
	"monolog/monolog",
	"psr/event-dispatcher",
	"psr/http-message",
	"psr/log",
	"ralouphie/getallheaders",
	"symfony/deprecation-contracts",
	"symfony/error-handler",
	"symfony/event-dispatcher",
	"symfony/event-dispatcher-contracts",
	"symfony/http-foundation",
	"symfony/http-kernel",
	"symfony/polyfill-ctype",
	"symfony/polyfill-mbstring",
	"symfony/polyfill-php73",
	"symfony/polyfill-php80",
	"symfony/polyfill-php83",
	"symfony/var-dumper",
}

func TestComposerLock(t *testing.T) {
	deps, err := (&ComposerLockParser{}).Parse(filepath.Join(composerFixture, "composer.lock"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	t.Run("reports the whole tree, not the three declared packages", func(t *testing.T) {
		if got := depNames(deps); !reflect.DeepEqual(got, composerAllPackages) {
			t.Errorf("parsed %v, want %v", got, composerAllPackages)
		}
	})

	t.Run("development packages are installed code too", func(t *testing.T) {
		// monolog arrives through "packages-dev", which composer installs into
		// the same vendor directory as everything else. A vulnerability there
		// runs in CI, and in any developer's working copy.
		d, ok := findDep(deps, "monolog/monolog")
		if !ok {
			t.Fatal("monolog/monolog missing: packages-dev was not read")
		}
		if !d.Direct {
			t.Error("monolog/monolog is declared in require-dev and is therefore direct")
		}
	})

	t.Run("only what composer.json requires is direct", func(t *testing.T) {
		direct := map[string]bool{
			"guzzlehttp/guzzle":   true,
			"symfony/http-kernel": true,
			"monolog/monolog":     true,
		}
		for _, d := range deps {
			if d.Direct != direct[d.Name] {
				t.Errorf("%s direct = %v, want %v", d.Name, d.Direct, direct[d.Name])
			}
		}
	})

	t.Run("the route records how a package was introduced", func(t *testing.T) {
		tests := []struct {
			name string
			want []string
		}{
			{"guzzlehttp/guzzle", nil},
			{"guzzlehttp/psr7", []string{"guzzlehttp/guzzle"}},
			{"psr/http-message", []string{"guzzlehttp/guzzle", "guzzlehttp/psr7"}},
			// Three hops down, and reachable no other way. This is the package
			// a manifest-only scan never sees and nobody can place by hand.
			{"psr/event-dispatcher", []string{
				"symfony/http-kernel",
				"symfony/event-dispatcher",
				"symfony/event-dispatcher-contracts",
			}},
			// psr/log is required by both monolog and symfony/http-kernel. The
			// shortest route wins, and monolog is queued first among the roots.
			{"psr/log", []string{"monolog/monolog"}},
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

	t.Run("versions are kept as the lockfile writes them", func(t *testing.T) {
		// Symfony tags its releases "v6.4.43". OSV normalises the prefix away
		// before matching, so rewriting it here would only make the reported
		// version differ from the one a developer greps the lockfile for.
		d, _ := findDep(deps, "symfony/http-kernel")
		if d.Version != "v5.4.0" {
			t.Errorf("symfony/http-kernel version = %q, want v5.4.0", d.Version)
		}
	})

	t.Run("platform requirements are not packages", func(t *testing.T) {
		// Every require block in this fixture mixes php and ext-* entries in
		// with the real dependencies. They describe the interpreter, cannot be
		// looked up in an advisory database, and would inflate the count.
		for _, d := range deps {
			if !isPackagistName(d.Name) {
				t.Errorf("%q is a platform requirement, not a Packagist package", d.Name)
			}
		}
	})

	t.Run("findings point at the lockfile", func(t *testing.T) {
		want := filepath.Join(composerFixture, "composer.lock")
		for _, d := range deps {
			if d.File != want {
				t.Errorf("%s attributed to %q, want %q", d.Name, d.File, want)
			}
			if d.Ecosystem != "packagist" {
				t.Errorf("%s ecosystem = %q, want packagist", d.Name, d.Ecosystem)
			}
		}
	})
}

// TestComposerLockWithoutManifest covers a lockfile committed on its own, or
// one reached without its sibling. composer.lock does not record what the root
// project asked for, so the split is lost — but the tree is not, and every
// installed package still has to be reported.
func TestComposerLockWithoutManifest(t *testing.T) {
	lock, err := os.ReadFile(filepath.Join(composerFixture, "composer.lock"))
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}
	dir := writeFiles(t, map[string]string{"composer.lock": string(lock)})

	deps, err := (&ComposerLockParser{}).Parse(filepath.Join(dir, "composer.lock"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if got := depNames(deps); !reflect.DeepEqual(got, composerAllPackages) {
		t.Errorf("parsed %v, want the full tree %v", got, composerAllPackages)
	}
	for _, d := range deps {
		if d.Direct {
			t.Errorf("%s cannot be known to be direct without composer.json", d.Name)
		}
		if len(d.Path) != 0 {
			t.Errorf("%s has route %v, but the walk has no root to start from", d.Name, d.Path)
		}
	}
}

// TestComposerLockResolvesEdgesCaseInsensitively guards the one thing a name
// key can get wrong. Composer matches package names case-insensitively, so a
// require block that spells a dependency "Monolog/Monolog" installs the same
// package as "monolog/monolog" — and an edge written that way still has to find
// its node, or the package it introduces is reported with no route.
func TestComposerLockResolvesEdgesCaseInsensitively(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"composer.json": `{"require":{"Acme/App":"^1.0"}}`,
		"composer.lock": `{
		  "packages": [
		    {"name":"acme/app","version":"1.0.0","require":{"php":">=7.2","Monolog/Monolog":"^1.25"}},
		    {"name":"monolog/monolog","version":"1.25.0"}
		  ],
		  "packages-dev": []
		}`,
	})

	deps, err := (&ComposerLockParser{}).Parse(filepath.Join(dir, "composer.lock"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	app, ok := findDep(deps, "acme/app")
	if !ok {
		t.Fatal("acme/app missing")
	}
	if !app.Direct {
		t.Error(`acme/app is required as "Acme/App" and is still the declared package`)
	}

	monolog, ok := findDep(deps, "monolog/monolog")
	if !ok {
		t.Fatal("monolog/monolog missing")
	}
	if want := []string{"acme/app"}; !reflect.DeepEqual(monolog.Path, want) {
		t.Errorf("monolog route = %v, want %v", monolog.Path, want)
	}
}

func TestComposerLockRejectsMalformedJSON(t *testing.T) {
	dir := writeFiles(t, map[string]string{"composer.lock": `{"packages": [`})

	if _, err := (&ComposerLockParser{}).Parse(filepath.Join(dir, "composer.lock")); err == nil {
		t.Error("Parse accepted a truncated lockfile")
	}
}

func TestInstalledComposer(t *testing.T) {
	deps, err := parseInstalledComposer(composerFixture)
	if err != nil {
		t.Fatalf("parseInstalledComposer returned error: %v", err)
	}

	t.Run("reads the same tree the lockfile describes", func(t *testing.T) {
		if got := depNames(deps); !reflect.DeepEqual(got, composerAllPackages) {
			t.Errorf("parsed %v, want %v", got, composerAllPackages)
		}
	})

	t.Run("routes survive the change of source", func(t *testing.T) {
		d, ok := findDep(deps, "psr/event-dispatcher")
		if !ok {
			t.Fatal("psr/event-dispatcher missing")
		}
		want := []string{
			"symfony/http-kernel",
			"symfony/event-dispatcher",
			"symfony/event-dispatcher-contracts",
		}
		if !reflect.DeepEqual(d.Path, want) {
			t.Errorf("route = %v, want %v", d.Path, want)
		}
	})

	t.Run("findings point at composer.json, not at vendor", func(t *testing.T) {
		// vendor/ is a build product and is usually not in the repository.
		// composer.json is the file a reader can open.
		want := filepath.Join(composerFixture, "composer.json")
		for _, d := range deps {
			if d.File != want {
				t.Errorf("%s attributed to %q, want %q", d.Name, d.File, want)
			}
		}
	})
}

// TestInstalledComposerV1 covers the other envelope. Composer 1 wrote
// installed.json as a bare array; Composer 2 wraps the same entries in an
// object that also names the development packages. A repository last installed
// with Composer 1 is exactly the kind that has no lockfile committed, so the
// older shape is the one this tier is most likely to meet.
func TestInstalledComposerV1(t *testing.T) {
	deps, err := parseInstalledComposer("testdata/composer1")
	if err != nil {
		t.Fatalf("parseInstalledComposer returned error: %v", err)
	}

	if got := depNames(deps); !reflect.DeepEqual(got, composerAllPackages) {
		t.Errorf("parsed %v, want %v", got, composerAllPackages)
	}
}

func TestInstalledComposerWithoutVendor(t *testing.T) {
	dir := writeFiles(t, map[string]string{"composer.json": `{"require":{"acme/app":"^1.0"}}`})

	deps, err := parseInstalledComposer(dir)
	if err == nil {
		t.Error("a missing vendor/composer/installed.json should be reported as an error")
	}
	if len(deps) != 0 {
		t.Errorf("returned %d dependencies with nothing installed", len(deps))
	}
}

// TestComposerLockTakesPrecedenceOverManifest pins the tier order for PHP. Both
// sources describe the same project, so merging them would report guzzle twice
// — once at 6.5.0 and once at the range composer.json asked for, which is not a
// version and matches no advisory.
func TestComposerLockTakesPrecedenceOverManifest(t *testing.T) {
	e := New(composerFixture)

	deps, err := e.collectDependencies()
	if err != nil {
		t.Fatalf("collectDependencies returned error: %v", err)
	}

	var packagist []Dependency
	for _, d := range deps {
		if d.Ecosystem == "packagist" {
			packagist = append(packagist, d)
		}
	}

	if len(packagist) != len(composerAllPackages) {
		t.Errorf("collected %d packagist dependencies, want %d — the manifest and the lockfile were both counted",
			len(packagist), len(composerAllPackages))
	}
	for _, d := range packagist {
		if filepath.Base(d.File) != "composer.lock" {
			t.Errorf("%s came from %s, but the lockfile covers this directory", d.Name, filepath.Base(d.File))
		}
	}
}

// TestInstalledComposerIsLastResort checks the tier below: with the lockfile
// gone, vendor/ still describes the full tree, and only with vendor/ gone as
// well does the scan fall back to the three declared names.
func TestInstalledComposerIsLastResort(t *testing.T) {
	installed, err := os.ReadFile(filepath.Join(composerFixture, "vendor", "composer", "installed.json"))
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}
	manifest, err := os.ReadFile(filepath.Join(composerFixture, "composer.json"))
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}

	dir := writeFiles(t, map[string]string{
		"composer.json":                  string(manifest),
		"vendor/composer/installed.json": string(installed),
	})

	deps, err := New(dir).collectDependencies()
	if err != nil {
		t.Fatalf("collectDependencies returned error: %v", err)
	}
	if got := depNames(deps); !reflect.DeepEqual(got, composerAllPackages) {
		t.Errorf("with no lockfile the installed tree should be read, got %v", got)
	}

	if err := os.RemoveAll(filepath.Join(dir, "vendor")); err != nil {
		t.Fatalf("removing vendor: %v", err)
	}

	deps, err = New(dir).collectDependencies()
	if err != nil {
		t.Fatalf("collectDependencies returned error: %v", err)
	}
	// What is left is composer.json: the two real packages it names, at ranges,
	// with php and ext-json dropped as platform requirements.
	want := []string{"guzzlehttp/guzzle", "monolog/monolog", "symfony/http-kernel"}
	if got := depNames(deps); !reflect.DeepEqual(got, want) {
		t.Errorf("manifest fallback parsed %v, want %v", got, want)
	}
}
