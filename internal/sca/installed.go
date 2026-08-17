package sca

import (
	"encoding/json"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

// maxInstalledPackages caps how many packages are read out of an installed
// tree. A node_modules directory of a large monorepo can hold tens of
// thousands, and reading every manifest in one is work with a falling return:
// past this point the scan is spending real time to add packages that a
// lockfile would have described for free.
const maxInstalledPackages = 20000

// parseInstalledNodeModules reads the dependency tree from node_modules on
// disk.
//
// It exists for the case a lockfile cannot cover: a repository that does not
// commit one. Without it such a project is scanned from package.json alone —
// its declared dependencies, at ranges — and everything those pull in is
// invisible, which is most of the code it ships. The scan succeeds, reports
// almost nothing, and the silence reads as safety.
//
// What is on disk is not a guess. Each installed package carries its own
// manifest with a resolved version, and the directory layout is the resolution:
// node_modules/express/node_modules/ms is a private copy that shadows the
// hoisted one for express. That is the same shape package-lock.json v3 records,
// so the graph walk written for it applies unchanged.
//
// This is deliberately not a network operation. Resolving ranges against a
// registry would produce a tree for what would be installed today, which is a
// different question from what is installed, and it would put a scan that
// currently runs in an air-gapped network on the far side of the internet.
func parseInstalledNodeModules(projectDir string) ([]Dependency, error) {
	root := filepath.Join(projectDir, "node_modules")

	nodes := make(map[string]node)

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // an unreadable subtree is skipped, not fatal
		}
		if d.IsDir() {
			// .bin holds symlinked executables, and dot-directories hold
			// package-manager bookkeeping. Neither contains packages.
			if name := d.Name(); name != "node_modules" && strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "package.json" {
			return nil
		}
		if len(nodes) >= maxInstalledPackages {
			return filepath.SkipAll
		}

		key, ok := installedKey(projectDir, filepath.Dir(path))
		if !ok {
			return nil
		}

		data, err := readManifestFile(path)
		if err != nil {
			return nil
		}
		var pkg struct {
			Name                 string            `json:"name"`
			Version              string            `json:"version"`
			Dependencies         map[string]string `json:"dependencies"`
			OptionalDependencies map[string]string `json:"optionalDependencies"`
		}
		if err := json.Unmarshal(data, &pkg); err != nil {
			return nil
		}
		if pkg.Name == "" || pkg.Version == "" {
			return nil
		}

		deps := make(map[string]string, len(pkg.Dependencies)+len(pkg.OptionalDependencies))
		for n, v := range pkg.Dependencies {
			deps[n] = v
		}
		for n, v := range pkg.OptionalDependencies {
			deps[n] = v
		}

		nodes[key] = node{name: pkg.Name, version: pkg.Version, deps: deps}
		return nil
	})
	if err != nil || len(nodes) == 0 {
		return nil, err
	}

	resolve := func(from, name, _ string) (string, bool) {
		return resolveNPM(nodes, from, name)
	}
	// The findings are attributed to package.json: it is the file a reader can
	// open, and node_modules is a build product rather than something in the
	// repository.
	manifest := filepath.Join(projectDir, "package.json")
	roots := declaredInPackageJSON(manifest)

	return walkGraph(nodes, roots, resolve, "npm", manifest), nil
}

// installedKey turns the directory a package occupies into the node_modules
// path key the resolver expects, and rejects anything that is not a package
// root. A manifest can sit anywhere inside a package — node_modules/foo/lib/
// package.json is common — and treating one as an installed package would
// invent a dependency that does not exist.
func installedKey(projectDir, packageDir string) (string, bool) {
	rel, err := filepath.Rel(projectDir, packageDir)
	if err != nil {
		return "", false
	}
	rel = filepath.ToSlash(rel)

	parts := strings.Split(rel, "/")
	if len(parts) < 2 {
		return "", false
	}

	// node_modules/<name>
	if parts[len(parts)-2] == "node_modules" {
		return rel, true
	}
	// node_modules/@scope/<name>
	if len(parts) >= 3 && parts[len(parts)-3] == "node_modules" && strings.HasPrefix(parts[len(parts)-2], "@") {
		return rel, true
	}
	return "", false
}

// npmProjectDirs lists, in a stable order, the directories holding an npm
// manifest.
func npmProjectDirs(deps []Dependency) []string {
	seen := make(map[string]bool)
	var dirs []string
	for _, dep := range deps {
		if dep.Ecosystem != "npm" {
			continue
		}
		dir := filepath.Dir(dep.File)
		if !seen[dir] {
			seen[dir] = true
			dirs = append(dirs, dir)
		}
	}
	sort.Strings(dirs)
	return dirs
}
