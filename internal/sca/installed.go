package sca

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
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

// parseInstalledComposer reads the dependency tree from vendor/composer/
// installed.json.
//
// Composer writes this file on every install, and it is the exact record of
// what landed in vendor/: a resolved version for every package, and each
// package's own require block. Where node_modules has to be walked and its
// layout interpreted, PHP hands over the whole graph in one file — the same
// shape composer.lock carries, so the same parsing serves both.
//
// It is read only for a project that does not commit its lockfile. That is
// common enough in PHP to matter: composer.lock is gitignored in plenty of
// library repositories, where committing it is in fact the documented advice,
// and without this such a project is scanned from composer.json alone — a
// handful of names at ranges, with the tree they pull in unseen.
func parseInstalledComposer(projectDir string) ([]Dependency, error) {
	path := filepath.Join(projectDir, "vendor", "composer", "installed.json")

	data, err := readManifestFile(path)
	if err != nil {
		return nil, err
	}

	// Composer 2 wraps the list in an object that also names the development
	// packages; Composer 1 writes the bare array. The first meaningful
	// character tells them apart, which is steadier than unmarshalling twice
	// and reading the failure as a format signal.
	var packages []composerPackage
	if bytes.HasPrefix(bytes.TrimLeft(data, " \t\r\n"), []byte("[")) {
		if err := json.Unmarshal(data, &packages); err != nil {
			return nil, err
		}
	} else {
		var installed struct {
			Packages []composerPackage `json:"packages"`
		}
		if err := json.Unmarshal(data, &installed); err != nil {
			return nil, err
		}
		packages = installed.Packages
	}

	nodes := composerNodes(packages)
	if len(nodes) == 0 {
		return nil, nil
	}

	// The findings are attributed to composer.json: it is the file in the
	// repository, while vendor/ is a build product that is usually not.
	manifest := filepath.Join(projectDir, "composer.json")
	roots := declaredInComposerJSON(manifest)

	return walkGraph(nodes, roots, composerResolver(nodes), "packagist", manifest), nil
}

// sitePackagesGlobs are where a project-local virtualenv puts its packages.
// A virtualenv anywhere else — one kept outside the repository, or the
// interpreter's own site-packages — is deliberately not searched: this tier
// answers "what is installed for this project", and a shared environment
// answers something else.
var sitePackagesGlobs = []string{
	".venv/lib/python*/site-packages",
	"venv/lib/python*/site-packages",
	// Windows lays it out without the interpreter version.
	".venv/Lib/site-packages",
	"venv/Lib/site-packages",
}

// parseInstalledPython reads the dependency tree from a project's virtualenv.
//
// Python's packaging metadata is per-installed-distribution rather than
// per-project: every package in site-packages carries a .dist-info/METADATA
// file naming itself, its version, and — in Requires-Dist — what it needs.
// Together those are the whole graph, which is why this tier gives routes where
// Pipfile.lock cannot.
//
// It is read only where no lockfile covers the project. Python is the ecosystem
// where that gap is widest: a repository can carry nothing but a pyproject.toml
// and a .venv, and pip itself writes no lockfile at all.
func parseInstalledPython(projectDir string) ([]Dependency, error) {
	var sitePackages string
	for _, pattern := range sitePackagesGlobs {
		matches, err := filepath.Glob(filepath.Join(projectDir, pattern))
		if err == nil && len(matches) > 0 {
			// A virtualenv built for several interpreter versions is unusual;
			// where it happens, the first in sorted order is taken so a scan is
			// reproducible rather than dependent on directory order.
			sort.Strings(matches)
			sitePackages = matches[0]
			break
		}
	}
	if sitePackages == "" {
		return nil, nil
	}

	entries, err := os.ReadDir(sitePackages)
	if err != nil {
		return nil, err
	}

	nodes := make(map[string]node)
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasSuffix(entry.Name(), ".dist-info") {
			continue
		}
		if len(nodes) >= maxInstalledPackages {
			break
		}

		name, version, requires, ok := readDistInfo(filepath.Join(sitePackages, entry.Name(), "METADATA"))
		if !ok {
			continue
		}

		deps := make(map[string]string, len(requires))
		for _, required := range requires {
			deps[required] = ""
		}
		nodes[normalizePythonName(name)] = node{name: name, version: version, deps: deps}
	}

	if len(nodes) == 0 {
		return nil, nil
	}

	// Findings are attributed to the manifest in the repository rather than to
	// the virtualenv, which is a build product. Which manifest that is depends
	// on the project; without any, the packages are still reported and only the
	// direct/transitive split is lost.
	manifest := pythonManifest(projectDir)
	return walkGraph(nodes, pythonRoots(manifest), pythonResolver(nodes), "pypi", manifest), nil
}

// readDistInfo reads the three fields this scanner needs out of an installed
// distribution's METADATA, which is an RFC 822-style header block followed by
// the project's README. Everything from the first blank line on is that
// README and is not parsed.
func readDistInfo(path string) (name, version string, requires []string, ok bool) {
	data, err := readManifestFile(path)
	if err != nil {
		return "", "", nil, false
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			break // the header block ends, the README begins
		}

		field, value, found := strings.Cut(line, ":")
		if !found {
			continue // a folded continuation line; none of our fields fold
		}
		value = strings.TrimSpace(value)

		switch field {
		case "Name":
			name = value
		case "Version":
			version = value
		case "Requires-Dist":
			if required := distRequirement(value); required != "" {
				requires = append(requires, required)
			}
		}
	}

	return name, version, requires, name != "" && version != ""
}

// distRequirement reads one Requires-Dist value into the normalised name it
// points at, and returns empty for the ones that are not edges of this install.
//
// A requirement gated behind an extra — "argon2-cffi (>=19.1.0) ; extra ==
// 'argon2'" — is not installed unless the extra was asked for, and following it
// would claim a dependency the project does not have. Other markers are left
// alone: "chardet ; python_version < \"3\"" simply resolves to nothing on a
// Python 3 environment, because chardet is not in site-packages to be found.
func distRequirement(value string) string {
	requirement, marker, _ := strings.Cut(value, ";")
	if strings.Contains(marker, "extra ==") {
		return ""
	}
	return normalizePythonName(requirementName(requirement))
}

// pythonManifest picks the file in the repository that a finding should point
// at, preferring the one that declares dependencies most completely.
func pythonManifest(projectDir string) string {
	for _, name := range []string{"pyproject.toml", "Pipfile", "requirements.txt"} {
		path := filepath.Join(projectDir, name)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return filepath.Join(projectDir, "pyproject.toml")
}

// pythonRoots reads the declared set out of whichever manifest was found.
func pythonRoots(manifest string) map[string]string {
	switch filepath.Base(manifest) {
	case "pyproject.toml":
		return declaredInPyProject(manifest)
	case "Pipfile":
		return declaredInPipfile(manifest)
	case "requirements.txt":
		return declaredInRequirements(manifest)
	}
	return nil
}

// projectDirs lists, in a stable order, the directories holding a manifest of
// one ecosystem.
func projectDirs(deps []Dependency, ecosystem string) []string {
	seen := make(map[string]bool)
	var dirs []string
	for _, dep := range deps {
		if dep.Ecosystem != ecosystem {
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
