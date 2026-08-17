package sca

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The fixture under testdata/pyvenv is a real virtualenv, built by pip from the
// pyproject.toml committed beside it:
//
//	docker run --rm python:3.11-slim sh -c \
//	  'python -m venv /v && /v/bin/pip install requests==2.27.0 django==3.2.12 jinja2==3.0.0'
//
// Each METADATA file keeps its header block verbatim and drops the body, which
// is the project's README and is not parsed. Thirteen distributions are
// installed for three declared: the ten they pull in, plus pip and setuptools,
// which the virtualenv brings in itself.
const pyvenvFixture = "testdata/pyvenv"

func TestInstalledPython(t *testing.T) {
	deps, err := parseInstalledPython(pyvenvFixture)
	if err != nil {
		t.Fatalf("parseInstalledPython returned error: %v", err)
	}

	t.Run("reads every installed distribution", func(t *testing.T) {
		want := []string{
			"Django", "Jinja2", "MarkupSafe", "asgiref", "certifi",
			"charset-normalizer", "idna", "pip", "pytz", "requests",
			"setuptools", "sqlparse", "urllib3",
		}
		if got := depNames(deps); !reflect.DeepEqual(got, want) {
			t.Errorf("parsed %v, want %v", got, want)
		}
	})

	t.Run("the name is reported as the distribution spells it", func(t *testing.T) {
		// The directory is Django-3.2.12.dist-info and METADATA says
		// "Name: Django". Matching happens in normalised form; reporting does
		// not, because the capitalised name is what the index shows.
		d, ok := findDep(deps, "Django")
		if !ok {
			t.Fatal("Django missing")
		}
		if d.Version != "3.2.12" {
			t.Errorf("Django version = %q, want 3.2.12", d.Version)
		}
	})

	t.Run("Requires-Dist gives the routes", func(t *testing.T) {
		// This is what the tier buys over Pipfile.lock: every installed
		// distribution carries its own requirements, so the graph is complete.
		tests := map[string][]string{
			"asgiref":            {"Django"},
			"urllib3":            {"requests"},
			"MarkupSafe":         {"Jinja2"},
			"charset-normalizer": {"requests"},
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

	t.Run("names in Requires-Dist are matched normalised", func(t *testing.T) {
		// Jinja2 requires "MarkupSafe (>=2.0.0rc2)" and the installed
		// distribution calls itself "MarkupSafe" — but the requests metadata
		// asks for "charset-normalizer" while the dist-info directory is
		// charset_normalizer. Only the normal form makes both resolve.
		d, _ := findDep(deps, "charset-normalizer")
		if len(d.Path) == 0 {
			t.Error("charset-normalizer has no route: the underscore spelling was not normalised")
		}
	})

	t.Run("requirements gated behind an extra are not edges", func(t *testing.T) {
		// requests declares "PySocks ... ; extra == 'socks'" and Django
		// declares argon2-cffi and bcrypt the same way. None is installed here,
		// and following those requirements would claim dependencies the project
		// does not have.
		for _, name := range []string{"PySocks", "argon2-cffi", "bcrypt"} {
			if _, ok := findDep(deps, name); ok {
				t.Errorf("%s is behind an extra and is not installed", name)
			}
		}
	})

	t.Run("a requirement no marker selected simply resolves to nothing", func(t *testing.T) {
		// requests declares chardet under python_version < "3". The marker is
		// not evaluated; the requirement just finds no installed distribution,
		// which is the same answer without the work.
		if _, ok := findDep(deps, "chardet"); ok {
			t.Error("chardet is not installed in a Python 3 environment")
		}
	})

	t.Run("what the virtualenv brought itself is reported without a route", func(t *testing.T) {
		// pip and setuptools are installed code and can carry advisories. They
		// are not reachable from anything the project declared, which is
		// exactly what "no route" means.
		for _, name := range []string{"pip", "setuptools"} {
			d, ok := findDep(deps, name)
			if !ok {
				t.Fatalf("%s missing: it is installed and can be vulnerable", name)
			}
			if d.Direct || len(d.Path) != 0 {
				t.Errorf("%s should carry no route, got direct=%v path=%v", name, d.Direct, d.Path)
			}
		}
	})

	t.Run("findings point at the manifest, not at the virtualenv", func(t *testing.T) {
		want := filepath.Join(pyvenvFixture, "pyproject.toml")
		for _, d := range deps {
			if d.File != want {
				t.Errorf("%s attributed to %q, want %q", d.Name, d.File, want)
			}
		}
	})

	t.Run("the manifest supplies the direct set", func(t *testing.T) {
		direct := map[string]bool{"requests": true, "Django": true, "Jinja2": true}
		for _, d := range deps {
			if d.Direct != direct[d.Name] {
				t.Errorf("%s direct = %v, want %v", d.Name, d.Direct, direct[d.Name])
			}
		}
	})
}

func TestInstalledPythonWithoutVirtualenv(t *testing.T) {
	dir := writeFiles(t, map[string]string{"pyproject.toml": `[project]
name = "app"
dependencies = ["requests==2.27.0"]`})

	deps, err := parseInstalledPython(dir)
	if err != nil {
		t.Errorf("a project with no virtualenv is not an error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("returned %d dependencies with nothing installed", len(deps))
	}
}

// TestInstalledPythonIsLastResort checks the tier order. With a lockfile
// present the virtualenv is not read at all, because a lockfile states what
// will be installed reproducibly while a virtualenv is one machine's state.
func TestInstalledPythonIsLastResort(t *testing.T) {
	lock, err := os.ReadFile(filepath.Join(uvFixture, "uv.lock"))
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}
	manifest, err := os.ReadFile(filepath.Join(pyvenvFixture, "pyproject.toml"))
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}
	metadata, err := os.ReadFile(filepath.Join(pyvenvFixture,
		".venv/lib/python3.11/site-packages/pip-24.0.dist-info/METADATA"))
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}

	files := map[string]string{
		"pyproject.toml": string(manifest),
		"uv.lock":        string(lock),
		// pip is installed but is in no lockfile, so it is the tell: if it
		// shows up, the virtualenv was read when it should not have been.
		".venv/lib/python3.11/site-packages/pip-24.0.dist-info/METADATA": string(metadata),
	}
	dir := writeFiles(t, files)

	deps, err := New(dir).collectDependencies()
	if err != nil {
		t.Fatalf("collectDependencies returned error: %v", err)
	}
	if _, ok := findDep(deps, "pip"); ok {
		t.Error("the virtualenv was read even though uv.lock covers this project")
	}
	for _, d := range deps {
		if filepath.Base(d.File) != "uv.lock" {
			t.Errorf("%s came from %s, but the lockfile covers this directory", d.Name, filepath.Base(d.File))
		}
	}

	// With the lockfile gone, the virtualenv is what is left.
	if err := os.Remove(filepath.Join(dir, "uv.lock")); err != nil {
		t.Fatalf("removing the lockfile: %v", err)
	}
	deps, err = New(dir).collectDependencies()
	if err != nil {
		t.Fatalf("collectDependencies returned error: %v", err)
	}
	if _, ok := findDep(deps, "pip"); !ok {
		t.Error("with no lockfile the virtualenv should be read")
	}
}

func TestPyProjectParser(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"pyproject.toml": `
[project]
name = "app"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = [
    "requests[socks] >= 2.27.0",
    "django==3.2.12",
    "Flask_SQLAlchemy",
]

[project.optional-dependencies]
docs = ["sphinx>=7"]

[dependency-groups]
dev = ["pytest==8.0.0"]

[tool.poetry.group.lint.dependencies]
ruff = "^0.6"
`,
	})

	deps, err := (&PyProjectParser{}).Parse(filepath.Join(dir, "pyproject.toml"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	t.Run("reads every table a project can declare in", func(t *testing.T) {
		want := []string{"Flask_SQLAlchemy", "django", "pytest", "requests", "ruff", "sphinx"}
		if got := depNames(deps); !reflect.DeepEqual(got, want) {
			t.Errorf("parsed %v, want %v", got, want)
		}
	})

	t.Run("only a pin is matchable", func(t *testing.T) {
		ranged := map[string]bool{
			"requests":         true,  // ">= 2.27.0" is a bound
			"django":           false, // "==3.2.12" is a pin
			"Flask_SQLAlchemy": true,  // no constraint at all
			"sphinx":           true,
			"pytest":           false,
			"ruff":             true, // "^0.6"
		}
		for _, d := range deps {
			if d.VersionIsRange != ranged[d.Name] {
				t.Errorf("%s %q VersionIsRange = %v, want %v", d.Name, d.Version, d.VersionIsRange, ranged[d.Name])
			}
		}
	})

	t.Run("an extras list is part of the name, not the version", func(t *testing.T) {
		d, ok := findDep(deps, "requests")
		if !ok {
			t.Fatal("requests missing")
		}
		if d.Version != "2.27.0" {
			t.Errorf("requests version = %q, want 2.27.0 — the [socks] extras list leaked into the specifier", d.Version)
		}
	})
}

func TestSplitRequirement(t *testing.T) {
	tests := map[string][2]string{
		"requests":                                 {"requests", ""},
		"requests>=2.27.0":                         {"requests", ">=2.27.0"},
		"requests[socks] >= 2.27.0":                {"requests", ">=2.27.0"},
		"django==3.2.12 ; python_version >= '3.9'": {"django", "==3.2.12"},
		"pillow (>=9.0.0)":                         {"pillow", "(>=9.0.0)"},
	}
	for in, want := range tests {
		name, spec := splitRequirement(in)
		// The specifier is compared with its internal spaces removed: the
		// parser that consumes it trims, and "  >= 2.27.0" and ">=2.27.0" are
		// the same requirement.
		if name != want[0] || normalizeSpace(spec) != want[1] {
			t.Errorf("splitRequirement(%q) = (%q, %q), want (%q, %q)", in, name, spec, want[0], want[1])
		}
	}
}

func normalizeSpace(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' {
			out = append(out, s[i])
		}
	}
	return string(out)
}
