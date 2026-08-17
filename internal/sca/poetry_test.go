package sca

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The fixture under testdata/poetry was produced by Poetry itself, from the
// pyproject.toml committed beside it:
//
//	docker run --rm python:3.11-slim sh -c 'pip install poetry && poetry lock'
//
// It is committed verbatim. Four declared dependencies resolve to twenty-six
// packages, and the tree is what makes the fixture worth having: jinja2
// requires "MarkupSafe" while the package satisfying it is locked as
// "markupsafe", and requests constrains two of its dependencies through tables
// with environment markers rather than plain strings. Both are the tool's own
// output and neither is something anyone would invent.
const poetryFixture = "testdata/poetry"

func TestPoetryLock(t *testing.T) {
	deps, err := (&PoetryLockParser{}).Parse(filepath.Join(poetryFixture, "poetry.lock"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	t.Run("reports the whole tree, not the four declared packages", func(t *testing.T) {
		if len(deps) != 26 {
			t.Errorf("parsed %d packages, want 26: %v", len(deps), depNames(deps))
		}
	})

	t.Run("only what pyproject.toml declares is direct", func(t *testing.T) {
		direct := map[string]bool{
			"celery":   true,
			"django":   true,
			"jinja2":   true,
			"requests": true,
		}
		for _, d := range deps {
			if d.Direct != direct[d.Name] {
				t.Errorf("%s direct = %v, want %v", d.Name, d.Direct, direct[d.Name])
			}
		}
	})

	t.Run("python is not a package", func(t *testing.T) {
		// [tool.poetry.dependencies] lists the interpreter alongside the real
		// dependencies. Treated as a root it resolves to nothing; reported as a
		// dependency it would be a name no index holds.
		if _, ok := findDep(deps, "python"); ok {
			t.Error("the interpreter constraint was reported as a dependency")
		}
	})

	t.Run("a development group is installed code too", func(t *testing.T) {
		// jinja2 is declared under [tool.poetry.group.dev.dependencies]. It is
		// installed by a plain `poetry install`, it runs in CI, and a flaw in it
		// is real.
		d, ok := findDep(deps, "jinja2")
		if !ok {
			t.Fatal("jinja2 missing: the dev group was not read")
		}
		if !d.Direct {
			t.Error("jinja2 is declared by the project and is direct")
		}
	})

	t.Run("names are matched in their normalised form", func(t *testing.T) {
		// This is the assertion the whole PEP 503 normalisation exists for.
		// jinja2's requirement is spelled "MarkupSafe"; the package that
		// satisfies it is locked as "markupsafe". Comparing the two literally
		// leaves markupsafe with no route — reported, but unexplained.
		d, ok := findDep(deps, "markupsafe")
		if !ok {
			t.Fatal("markupsafe missing")
		}
		if want := []string{"jinja2"}; !reflect.DeepEqual(d.Path, want) {
			t.Errorf(`markupsafe route = %v, want %v — the edge is written "MarkupSafe"`, d.Path, want)
		}
	})

	t.Run("an edge written as a table resolves like any other", func(t *testing.T) {
		// requests constrains charset-normalizer and idna through tables
		// carrying environment markers, not plain constraint strings. The
		// lockfile has already picked the version, so the shape of the value
		// carries nothing this scanner needs.
		for _, name := range []string{"charset-normalizer", "idna"} {
			d, ok := findDep(deps, name)
			if !ok {
				t.Fatalf("%s missing", name)
			}
			if want := []string{"requests"}; !reflect.DeepEqual(d.Path, want) {
				t.Errorf("%s route = %v, want %v", name, d.Path, want)
			}
		}
	})

	t.Run("the route reaches the bottom of a deep tree", func(t *testing.T) {
		d, ok := findDep(deps, "wcwidth")
		if !ok {
			t.Fatal("wcwidth missing")
		}
		want := []string{"celery", "click-repl", "prompt-toolkit"}
		if !reflect.DeepEqual(d.Path, want) {
			t.Errorf("route = %v, want %v", d.Path, want)
		}
	})

	t.Run("the shortest route wins where there are several", func(t *testing.T) {
		// vine is required by celery directly and by kombu, which celery also
		// pulls in. The one-hop route is the one a developer can act on.
		d, ok := findDep(deps, "vine")
		if !ok {
			t.Fatal("vine missing")
		}
		if want := []string{"celery"}; !reflect.DeepEqual(d.Path, want) {
			t.Errorf("vine route = %v, want %v", d.Path, want)
		}
	})

	t.Run("versions are kept as the lockfile writes them", func(t *testing.T) {
		// "2026.3.post1" is a PEP 440 post-release. Trimming it to look like
		// semver would name a version that was never published.
		d, _ := findDep(deps, "pytz")
		if d.Version != "2026.3.post1" {
			t.Errorf("pytz version = %q, want 2026.3.post1", d.Version)
		}
	})

	t.Run("findings point at the lockfile", func(t *testing.T) {
		want := filepath.Join(poetryFixture, "poetry.lock")
		for _, d := range deps {
			if d.File != want {
				t.Errorf("%s attributed to %q, want %q", d.Name, d.File, want)
			}
			if d.Ecosystem != "pypi" {
				t.Errorf("%s ecosystem = %q, want pypi", d.Name, d.Ecosystem)
			}
		}
	})
}

// TestPoetryLockWithoutPyProject covers a lockfile reached without its sibling.
// poetry.lock does not record what the project asked for, so the split is lost —
// but the tree is not.
func TestPoetryLockWithoutPyProject(t *testing.T) {
	lock, err := os.ReadFile(filepath.Join(poetryFixture, "poetry.lock"))
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}
	dir := writeFiles(t, map[string]string{"poetry.lock": string(lock)})

	deps, err := (&PoetryLockParser{}).Parse(filepath.Join(dir, "poetry.lock"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if len(deps) != 26 {
		t.Errorf("parsed %d packages, want the full tree of 26", len(deps))
	}
	for _, d := range deps {
		if d.Direct || len(d.Path) != 0 {
			t.Errorf("%s was given a route, but there is no manifest to start the walk from", d.Name)
		}
	}
}

// TestPoetryLockReadsPEP621Dependencies covers the other manifest layout. A
// Poetry 2 project can declare its dependencies in the standard [project] table
// as requirement strings, leaving Poetry to manage only the groups — so the
// direct set has to be read from both places.
func TestPoetryLockReadsPEP621Dependencies(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"pyproject.toml": `
[project]
name = "app"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = [
    "requests[socks] >= 2.27.0",
    "Flask_SQLAlchemy==3.0.0 ; python_version >= '3.9'",
]

[project.optional-dependencies]
docs = ["sphinx>=7"]

[tool.poetry.group.dev.dependencies]
pytest = "^8.0"
`,
		"poetry.lock": `
[[package]]
name = "requests"
version = "2.27.0"

[[package]]
name = "flask-sqlalchemy"
version = "3.0.0"

[[package]]
name = "sphinx"
version = "7.2.6"

[[package]]
name = "pytest"
version = "8.0.0"

[[package]]
name = "unasked-for"
version = "1.0.0"
`,
	})

	deps, err := (&PoetryLockParser{}).Parse(filepath.Join(dir, "poetry.lock"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	direct := map[string]bool{
		// The extras marker and the environment marker are part of the
		// requirement, not of the name.
		"requests": true,
		// Declared as "Flask_SQLAlchemy", locked as "flask-sqlalchemy".
		"flask-sqlalchemy": true,
		// An optional-dependencies group is still something the project names.
		"sphinx": true,
		// Poetry's own group tables are read alongside [project].
		"pytest": true,
	}
	for _, d := range deps {
		if d.Direct != direct[d.Name] {
			t.Errorf("%s direct = %v, want %v", d.Name, d.Direct, direct[d.Name])
		}
	}
}

func TestPoetryLockRejectsMalformedTOML(t *testing.T) {
	dir := writeFiles(t, map[string]string{"poetry.lock": "[[package]\nname = "})

	if _, err := (&PoetryLockParser{}).Parse(filepath.Join(dir, "poetry.lock")); err == nil {
		t.Error("Parse accepted a truncated lockfile")
	}
}

// TestPoetryLockTakesPrecedenceOverRequirements pins the tier order for Python.
// A project can carry both, and counting both reports every declared package
// twice — the second time at whatever range requirements.txt happens to hold.
func TestPoetryLockTakesPrecedenceOverRequirements(t *testing.T) {
	lock, err := os.ReadFile(filepath.Join(poetryFixture, "poetry.lock"))
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}
	manifest, err := os.ReadFile(filepath.Join(poetryFixture, "pyproject.toml"))
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}

	dir := writeFiles(t, map[string]string{
		"poetry.lock":      string(lock),
		"pyproject.toml":   string(manifest),
		"requirements.txt": "requests==2.27.0\ndjango==3.2.12\n",
	})

	deps, err := New(dir).collectDependencies()
	if err != nil {
		t.Fatalf("collectDependencies returned error: %v", err)
	}

	if len(deps) != 26 {
		t.Errorf("collected %d packages, want 26 — requirements.txt was counted as well", len(deps))
	}
	for _, d := range deps {
		if filepath.Base(d.File) != "poetry.lock" {
			t.Errorf("%s came from %s, but the lockfile covers this directory", d.Name, filepath.Base(d.File))
		}
	}
}

func TestNormalizePythonName(t *testing.T) {
	// The cases PEP 503 calls equivalent, plus the shapes that would otherwise
	// produce a key matching nothing.
	tests := map[string]string{
		"MarkupSafe":         "markupsafe",
		"Flask_SQLAlchemy":   "flask-sqlalchemy",
		"Flask.SQLAlchemy":   "flask-sqlalchemy",
		"flask--sqlalchemy":  "flask-sqlalchemy",
		"zope.interface":     "zope-interface",
		"backports.zoneinfo": "backports-zoneinfo",
		"  requests  ":       "requests",
		"_leading":           "leading",
		"trailing_":          "trailing",
		"":                   "",
	}
	for in, want := range tests {
		if got := normalizePythonName(in); got != want {
			t.Errorf("normalizePythonName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRequirementName(t *testing.T) {
	tests := map[string]string{
		"requests":                                 "requests",
		"requests>=2.27.0":                         "requests",
		"requests [socks] >= 2.27.0":               "requests",
		"django==3.2.12 ; python_version >= '3.9'": "django",
		"pillow (>=9.0.0)":                         "pillow",
		"urllib3!=1.25.0,!=1.25.1,<1.27":           "urllib3",
		"zope.interface~=5.4":                      "zope.interface",
	}
	for in, want := range tests {
		if got := requirementName(in); got != want {
			t.Errorf("requirementName(%q) = %q, want %q", in, got, want)
		}
	}
}
