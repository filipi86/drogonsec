package sca

import (
	"path/filepath"
	"reflect"
	"testing"
)

// installedTree lays out a node_modules directory the way npm does: everything
// hoisted to the top except the copy express needs privately, which sits inside
// its own node_modules and shadows the hoisted one.
func installedTree(t *testing.T) string {
	t.Helper()
	return writeFiles(t, map[string]string{
		"package.json": `{"name":"app","dependencies":{"express":"^4.17.1"},"devDependencies":{"jest":"^29.0.0"}}`,

		"node_modules/express/package.json": `{"name":"express","version":"4.17.1",
		  "dependencies":{"accepts":"~1.3.7","ms":"2.0.0"}}`,
		"node_modules/express/node_modules/ms/package.json": `{"name":"ms","version":"2.0.0"}`,

		"node_modules/accepts/package.json": `{"name":"accepts","version":"1.3.8",
		  "dependencies":{"mime-types":"~2.1.34"}}`,
		"node_modules/mime-types/package.json":  `{"name":"mime-types","version":"2.1.35"}`,
		"node_modules/ms/package.json":          `{"name":"ms","version":"2.1.3"}`,
		"node_modules/jest/package.json":        `{"name":"jest","version":"29.7.0"}`,
		"node_modules/@babel/core/package.json": `{"name":"@babel/core","version":"7.20.0"}`,

		// Not packages: a manifest deep inside one, and a package-manager
		// bookkeeping directory.
		"node_modules/express/lib/package.json":    `{"name":"express-internal","version":"9.9.9"}`,
		"node_modules/.package-lock.json":          `{"name":"bookkeeping","version":"1.0.0"}`,
		"node_modules/.bin/something/package.json": `{"name":"binstub","version":"1.0.0"}`,
	})
}

func TestInstalledNodeModules(t *testing.T) {
	dir := installedTree(t)

	deps, err := parseInstalledNodeModules(dir)
	if err != nil {
		t.Fatalf("parseInstalledNodeModules returned error: %v", err)
	}

	t.Run("reads the installed tree", func(t *testing.T) {
		want := []string{"@babel/core", "accepts", "express", "jest", "mime-types", "ms", "ms"}
		if got := depNames(deps); !reflect.DeepEqual(got, want) {
			t.Errorf("parsed %v, want %v", got, want)
		}
	})

	t.Run("only package roots count", func(t *testing.T) {
		// A manifest inside a package is not an installed package. Counting one
		// would invent a dependency that is not there, and inventing a
		// dependency in a security report is worse than missing one: it sends
		// somebody to fix nothing.
		for _, d := range deps {
			switch d.Name {
			case "express-internal", "binstub", "bookkeeping":
				t.Errorf("%s is not an installed package", d.Name)
			}
		}
	})

	t.Run("what package.json declares is direct", func(t *testing.T) {
		for _, name := range []string{"express", "jest"} {
			if d, _ := findDep(deps, name); !d.Direct {
				t.Errorf("%s is declared and should be direct", name)
			}
		}
		if d, _ := findDep(deps, "accepts"); d.Direct {
			t.Error("accepts is hoisted, not declared")
		}
	})

	t.Run("routes follow the directory layout", func(t *testing.T) {
		if d, _ := findDep(deps, "accepts"); !reflect.DeepEqual(d.Path, []string{"express"}) {
			t.Errorf("accepts route = %v, want [express]", d.Path)
		}
		if d, _ := findDep(deps, "mime-types"); !reflect.DeepEqual(d.Path, []string{"express", "accepts"}) {
			t.Errorf("mime-types route = %v, want [express accepts]", d.Path)
		}
	})

	t.Run("a nested copy shadows the hoisted one", func(t *testing.T) {
		// express requires ms 2.0.0 and has its own copy; 2.1.3 sits hoisted
		// for anything else. Both are installed and both must be reported, or
		// an advisory against one version is checked against the other.
		var nested, hoisted bool
		for _, d := range deps {
			if d.Name != "ms" {
				continue
			}
			switch d.Version {
			case "2.0.0":
				nested = true
				if !reflect.DeepEqual(d.Path, []string{"express"}) {
					t.Errorf("nested ms route = %v, want [express]", d.Path)
				}
			case "2.1.3":
				hoisted = true
			}
		}
		if !nested || !hoisted {
			t.Errorf("expected both installed copies of ms, nested=%v hoisted=%v", nested, hoisted)
		}
	})

	t.Run("findings point at package.json, not at the build product", func(t *testing.T) {
		// node_modules is not in the repository; package.json is the file a
		// reader can open and act on.
		want := filepath.Join(dir, "package.json")
		for _, d := range deps {
			if d.File != want {
				t.Errorf("%s attributed to %q, want %q", d.Name, d.File, want)
			}
		}
	})
}

// TestInstalledTreeIsLastResort pins the order of the sources. A lockfile is
// the reproducible description of what will be installed; node_modules is one
// machine's current state, which can be stale and is absent until somebody runs
// an install.
func TestInstalledTreeIsLastResort(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"package.json":      `{"dependencies":{"express":"^4.17.1"}}`,
		"package-lock.json": lockV3,
		// The installed tree disagrees with the lockfile: a stale install.
		"node_modules/express/package.json": `{"name":"express","version":"3.0.0"}`,
	})

	deps, err := New(dir).collectDependencies()
	if err != nil {
		t.Fatalf("collectDependencies returned error: %v", err)
	}

	d, ok := findDep(deps, "express")
	if !ok {
		t.Fatal("express missing")
	}
	if d.Version != "4.17.1" {
		t.Errorf("express version = %q, want the lockfile's 4.17.1", d.Version)
	}
	if _, ok := findDep(deps, "side-channel"); !ok {
		t.Error("expected the lockfile tree, which contains side-channel")
	}
}

// TestInstalledTreeReplacesTheManifest is the case the whole file exists for: a
// repository that does not commit a lockfile. Reading package.json alone finds
// one package; the installed tree finds what actually ships.
func TestInstalledTreeReplacesTheManifest(t *testing.T) {
	dir := installedTree(t)

	deps, err := New(dir).collectDependencies()
	if err != nil {
		t.Fatalf("collectDependencies returned error: %v", err)
	}

	if len(deps) < 6 {
		t.Fatalf("got %d dependencies, want the installed tree rather than the two declared", len(deps))
	}

	// The manifest's own entries must not be folded in on top: express would
	// otherwise appear twice, once at "^4.17.1", which matches no advisory.
	count := 0
	for _, d := range deps {
		if d.Name == "express" {
			count++
			if d.Version != "4.17.1" {
				t.Errorf("express version = %q, want the installed 4.17.1", d.Version)
			}
		}
	}
	if count != 1 {
		t.Errorf("express reported %d times, want once", count)
	}
}

// TestInstalledKeyRejectsNonPackages covers the path check on its own, since it
// is what stands between the walker and inventing dependencies out of manifests
// that happen to live inside a package.
func TestInstalledKeyRejectsNonPackages(t *testing.T) {
	const project = "/repo"

	tests := []struct {
		dir  string
		want string
		ok   bool
	}{
		{"/repo/node_modules/express", "node_modules/express", true},
		{"/repo/node_modules/@babel/core", "node_modules/@babel/core", true},
		{"/repo/node_modules/express/node_modules/ms", "node_modules/express/node_modules/ms", true},
		{"/repo/node_modules/express/lib", "", false},
		{"/repo/node_modules/express/node_modules/ms/dist", "", false},
		{"/repo", "", false},
	}

	for _, tt := range tests {
		got, ok := installedKey(project, filepath.FromSlash(tt.dir))
		if ok != tt.ok || got != tt.want {
			t.Errorf("installedKey(%q) = (%q, %v), want (%q, %v)", tt.dir, got, ok, tt.want, tt.ok)
		}
	}
}
