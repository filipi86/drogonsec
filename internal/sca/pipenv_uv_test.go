package sca

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The fixtures under testdata/pipenv and testdata/uv were produced by the tools
// themselves, from the Pipfile and pyproject.toml committed beside them:
//
//	docker run --rm python:3.11-slim sh -c 'pip install pipenv && pipenv lock'
//	docker run --rm python:3.11-slim sh -c 'pip install uv && uv lock'
//
// Both projects declare the same three packages, so the two tiers can be
// compared against each other and against testdata/poetry.
const (
	pipenvFixture = "testdata/pipenv"
	uvFixture     = "testdata/uv"
)

func TestPipfileLock(t *testing.T) {
	deps, err := (&PipfileLockParser{}).Parse(filepath.Join(pipenvFixture, "Pipfile.lock"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	t.Run("reports the whole set, not the three declared packages", func(t *testing.T) {
		want := []string{
			"asgiref", "certifi", "charset-normalizer", "django", "idna",
			"jinja2", "markupsafe", "pytz", "requests", "sqlparse", "urllib3",
		}
		if got := depNames(deps); !reflect.DeepEqual(got, want) {
			t.Errorf("parsed %v, want %v", got, want)
		}
	})

	t.Run("develop packages are read alongside default", func(t *testing.T) {
		// jinja2 and markupsafe live in "develop". They are installed into the
		// same environment as everything else.
		for _, name := range []string{"jinja2", "markupsafe"} {
			if _, ok := findDep(deps, name); !ok {
				t.Errorf("%s missing: the develop group was not read", name)
			}
		}
	})

	t.Run("the resolved version is unwrapped from its operator", func(t *testing.T) {
		// Pipenv writes "==3.12.1". It is a pin, so it stays matchable.
		d, ok := findDep(deps, "asgiref")
		if !ok {
			t.Fatal("asgiref missing")
		}
		if d.Version != "3.12.1" {
			t.Errorf("asgiref version = %q, want 3.12.1", d.Version)
		}
		if d.VersionIsRange {
			t.Error("a locked == version is a pin and must reach the advisory query")
		}
	})

	t.Run("the Pipfile supplies the direct set", func(t *testing.T) {
		direct := map[string]bool{"requests": true, "django": true, "jinja2": true}
		for _, d := range deps {
			if d.Direct != direct[d.Name] {
				t.Errorf("%s direct = %v, want %v", d.Name, d.Direct, direct[d.Name])
			}
		}
	})

	t.Run("no routes, because the file records no edges", func(t *testing.T) {
		// This is the tier's honest limit. Pipfile.lock is a flat map with
		// nothing saying which package asked for which, so a transitive finding
		// can be reported but not explained. Inventing a route would be worse
		// than admitting there is none.
		for _, d := range deps {
			if len(d.Path) != 0 {
				t.Errorf("%s carries route %v, which Pipfile.lock cannot support", d.Name, d.Path)
			}
			if len(d.Requires) != 0 {
				t.Errorf("%s carries edges %v, which Pipfile.lock does not record", d.Name, d.Requires)
			}
		}
	})
}

func TestPipfileLockWithoutPipfile(t *testing.T) {
	lock, err := os.ReadFile(filepath.Join(pipenvFixture, "Pipfile.lock"))
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}
	dir := writeFiles(t, map[string]string{"Pipfile.lock": string(lock)})

	deps, err := (&PipfileLockParser{}).Parse(filepath.Join(dir, "Pipfile.lock"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(deps) != 11 {
		t.Errorf("parsed %d packages, want the full set of 11", len(deps))
	}
	for _, d := range deps {
		if d.Direct {
			t.Errorf("%s cannot be known to be direct without the Pipfile", d.Name)
		}
	}
}

// TestPipfileLockSkipsUnversionedEntries covers a package installed from
// version control. Pipenv records the ref rather than a version, and there is
// nothing for an advisory to be matched against.
func TestPipfileLockSkipsUnversionedEntries(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"Pipfile.lock": `{
		  "_meta": {"hash": {"sha256": "x"}},
		  "default": {
		    "requests": {"version": "==2.27.0"},
		    "internal": {"git": "https://example.test/internal.git", "ref": "abc123"},
		    "anything": {"version": "*"}
		  },
		  "develop": {}
		}`,
	})

	deps, err := (&PipfileLockParser{}).Parse(filepath.Join(dir, "Pipfile.lock"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	ranged := map[string]bool{"requests": false, "internal": true, "anything": true}
	for _, d := range deps {
		if d.VersionIsRange != ranged[d.Name] {
			t.Errorf("%s %q VersionIsRange = %v, want %v", d.Name, d.Version, d.VersionIsRange, ranged[d.Name])
		}
	}
}

func TestUVLock(t *testing.T) {
	deps, err := (&UVLockParser{}).Parse(filepath.Join(uvFixture, "uv.lock"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	t.Run("reports the tree without the project itself", func(t *testing.T) {
		// drogonsec-fixture is the project: its source is "virtual", not a
		// registry, so it is what depends rather than a dependency.
		want := []string{
			"asgiref", "certifi", "charset-normalizer", "django", "idna",
			"jinja2", "markupsafe", "pytz", "requests", "sqlparse", "urllib3",
		}
		if got := depNames(deps); !reflect.DeepEqual(got, want) {
			t.Errorf("parsed %v, want %v", got, want)
		}
	})

	t.Run("the lockfile names its own direct set", func(t *testing.T) {
		// Unlike poetry.lock and Pipfile.lock, uv.lock needs no sibling
		// manifest: the virtual root's dependencies are the declared ones, and
		// its dev-dependencies groups are read alongside them.
		direct := map[string]bool{"requests": true, "django": true, "jinja2": true}
		for _, d := range deps {
			if d.Direct != direct[d.Name] {
				t.Errorf("%s direct = %v, want %v", d.Name, d.Direct, direct[d.Name])
			}
		}
	})

	t.Run("routes come back", func(t *testing.T) {
		// uv records edges, so unlike Pipfile.lock this tier can say why a
		// package is present.
		tests := map[string][]string{
			"urllib3":    {"requests"},
			"markupsafe": {"jinja2"},
			"asgiref":    {"django"},
		}
		for name, want := range tests {
			d, ok := findDep(deps, name)
			if !ok {
				t.Fatalf("%s missing", name)
			}
			if !reflect.DeepEqual(d.Path, want) {
				t.Errorf("%s route = %v, want %v", name, d.Path, want)
			}
		}
	})

	t.Run("edges are carried for the SBOM", func(t *testing.T) {
		d, _ := findDep(deps, "requests")
		want := []Ref{
			{Name: "certifi", Version: "2026.7.22"},
			{Name: "charset-normalizer", Version: "2.0.12"},
			{Name: "idna", Version: "3.18"},
			{Name: "urllib3", Version: "1.26.20"},
		}
		if !reflect.DeepEqual(d.Requires, want) {
			t.Errorf("requests requires %v, want %v", d.Requires, want)
		}
	})
}

// TestPythonTiersAgree is the check that matters most across three parsers of
// one ecosystem: given the same declared packages, they resolve the same set.
// A disagreement means one of them is dropping or inventing something.
func TestPythonTiersAgree(t *testing.T) {
	poetry, err := (&PoetryLockParser{}).Parse(filepath.Join(poetryFixture, "poetry.lock"))
	if err != nil {
		t.Fatalf("poetry: %v", err)
	}
	pipenv, err := (&PipfileLockParser{}).Parse(filepath.Join(pipenvFixture, "Pipfile.lock"))
	if err != nil {
		t.Fatalf("pipenv: %v", err)
	}
	uv, err := (&UVLockParser{}).Parse(filepath.Join(uvFixture, "uv.lock"))
	if err != nil {
		t.Fatalf("uv: %v", err)
	}

	// The poetry fixture declares celery on top of the three the others share,
	// so compare only what all three were asked for.
	shared := map[string]bool{
		"asgiref": true, "certifi": true, "charset-normalizer": true,
		"django": true, "idna": true, "jinja2": true, "markupsafe": true,
		"pytz": true, "requests": true, "sqlparse": true, "urllib3": true,
	}
	versions := func(deps []Dependency) map[string]string {
		out := make(map[string]string)
		for _, d := range deps {
			if shared[d.Name] {
				out[d.Name] = d.Version
			}
		}
		return out
	}

	poetryVersions := versions(poetry)
	if len(poetryVersions) != len(shared) {
		t.Fatalf("the poetry fixture resolved %d of the %d shared packages", len(poetryVersions), len(shared))
	}
	if got := versions(pipenv); !reflect.DeepEqual(got, poetryVersions) {
		t.Errorf("pipenv resolved %v, poetry resolved %v", got, poetryVersions)
	}
	if got := versions(uv); !reflect.DeepEqual(got, poetryVersions) {
		t.Errorf("uv resolved %v, poetry resolved %v", got, poetryVersions)
	}
}

func TestUVLockRejectsMalformedTOML(t *testing.T) {
	dir := writeFiles(t, map[string]string{"uv.lock": "[[package]\nname = "})

	if _, err := (&UVLockParser{}).Parse(filepath.Join(dir, "uv.lock")); err == nil {
		t.Error("Parse accepted a truncated lockfile")
	}
}

func TestPipfileLockRejectsMalformedJSON(t *testing.T) {
	dir := writeFiles(t, map[string]string{"Pipfile.lock": `{"default": {`})

	if _, err := (&PipfileLockParser{}).Parse(filepath.Join(dir, "Pipfile.lock")); err == nil {
		t.Error("Parse accepted a truncated lockfile")
	}
}
