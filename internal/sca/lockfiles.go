package sca

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

// LockfileParser is a ManifestParser that reads a resolved dependency graph
// rather than a declaration of intent.
//
// The difference decides what a scan can report. A manifest states what the
// project asked for — "express": "^4.17.1" — which is a range, not a version,
// and it lists only what the project asked for directly. A lockfile states what
// was actually installed: an exact version for every package in the tree,
// including the ones no human ever named. Vulnerabilities overwhelmingly live
// in that second group, so a scanner reading only manifests reports on a small
// fraction of the code that ships.
//
// The engine treats the two differently: when a lockfile covers a directory,
// the manifest for the same ecosystem in that directory is discarded rather
// than merged, because the manifest would otherwise contribute the same direct
// dependencies a second time, at a range instead of a version.
type LockfileParser interface {
	ManifestParser

	// Lockfile marks the implementation. It exists to be type-asserted for and
	// carries no value of its own.
	Lockfile()
}

// ============= npm =============

// PackageLockParser parses npm's package-lock.json in all three of its
// formats. Lockfile version 1 (npm 6) keys a nested tree under "dependencies";
// versions 2 and 3 (npm 7 and later) key a flat map under "packages" by
// installation path. Version 2 carries both for backward compatibility, and
// the flat map is preferred when present because it records the root project's
// own declarations, which is what makes a direct dependency distinguishable
// from a hoisted transitive one.
type PackageLockParser struct{}

func (p *PackageLockParser) Name() string    { return "npm (lockfile)" }
func (p *PackageLockParser) Files() []string { return []string{"package-lock.json"} }
func (p *PackageLockParser) Lockfile()       {}

// packageLock covers the parts of package-lock.json this parser reads. Fields
// absent from a given lockfile version simply stay empty.
type packageLock struct {
	LockfileVersion int                    `json:"lockfileVersion"`
	Packages        map[string]lockEntryV3 `json:"packages"`
	Dependencies    map[string]lockEntryV1 `json:"dependencies"`
}

// lockEntryV3 is one entry of the v2/v3 "packages" map, keyed by installation
// path ("node_modules/express", "node_modules/express/node_modules/cookie").
type lockEntryV3 struct {
	Version              string            `json:"version"`
	Link                 bool              `json:"link"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

// lockEntryV1 is one node of the v1 "dependencies" tree. It nests: a package
// whose own requirement conflicts with the hoisted version gets its private
// copy under the parent's "dependencies".
type lockEntryV1 struct {
	Version      string                 `json:"version"`
	Requires     map[string]string      `json:"requires"`
	Dependencies map[string]lockEntryV1 `json:"dependencies"`
}

// node is the shape both lockfile formats are normalised into before the graph
// is walked: an installation path, a resolved version, and the names this node
// depends on. Reducing v1 and v3 to the same shape means the traversal that
// works out what is reachable, and by which route, is written once.
type node struct {
	name    string
	version string
	deps    map[string]string
}

func (p *PackageLockParser) Parse(path string) ([]Dependency, error) {
	data, err := readManifestFile(path)
	if err != nil {
		return nil, err
	}

	var lock packageLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	nodes, roots := normaliseNPMLock(&lock, path)
	if len(nodes) == 0 {
		return nil, nil
	}

	resolve := func(from, name, _ string) (string, bool) {
		return resolveNPM(nodes, from, name)
	}
	return walkGraph(nodes, roots, resolve, "npm", path), nil
}

// normaliseNPMLock reduces either lockfile layout to the common node map, and
// returns what the root project declares for itself.
func normaliseNPMLock(lock *packageLock, path string) (map[string]node, map[string]string) {
	if len(lock.Packages) > 0 {
		return normaliseV3(lock)
	}
	return normaliseV1(lock, path)
}

func normaliseV3(lock *packageLock) (map[string]node, map[string]string) {
	nodes := make(map[string]node, len(lock.Packages))
	roots := make(map[string]string)

	for key, entry := range lock.Packages {
		// The empty key is the project itself: it holds no version of interest,
		// only the list of what the project actually asked for. That list is
		// the sole way to tell a direct dependency from a transitive one that
		// npm hoisted to the top of node_modules alongside it.
		if key == "" {
			for _, m := range []map[string]string{entry.Dependencies, entry.DevDependencies, entry.OptionalDependencies} {
				for name, constraint := range m {
					roots[name] = constraint
				}
			}
			continue
		}
		// Workspace members are symlinks into the repository, not published
		// packages, and carry no version to match an advisory against.
		if entry.Link || entry.Version == "" || !strings.Contains(key, "node_modules/") {
			continue
		}

		deps := make(map[string]string, len(entry.Dependencies)+len(entry.OptionalDependencies))
		for n, v := range entry.Dependencies {
			deps[n] = v
		}
		for n, v := range entry.OptionalDependencies {
			deps[n] = v
		}

		nodes[key] = node{name: npmNameFromKey(key), version: entry.Version, deps: deps}
	}

	return nodes, roots
}

// normaliseV1 flattens the nested v1 tree into the same path-keyed map the v3
// layout already uses, so one traversal serves both. A v1 lockfile does not
// record what the project declared, so the sibling package.json is consulted
// for that; without it every package is reported, but none can be called
// direct.
func normaliseV1(lock *packageLock, path string) (map[string]node, map[string]string) {
	nodes := make(map[string]node)

	var flatten func(prefix string, entries map[string]lockEntryV1)
	flatten = func(prefix string, entries map[string]lockEntryV1) {
		for name, entry := range entries {
			key := prefix + "node_modules/" + name
			if entry.Version != "" {
				nodes[key] = node{name: name, version: entry.Version, deps: entry.Requires}
			}
			if len(entry.Dependencies) > 0 {
				flatten(key+"/", entry.Dependencies)
			}
		}
	}
	flatten("", lock.Dependencies)

	return nodes, declaredInPackageJSON(filepath.Join(filepath.Dir(path), "package.json"))
}

// declaredInPackageJSON reads what the project declares, as name to version
// range. A missing or unreadable package.json is not an error: the lockfile
// still describes every installed package, and the only thing lost is the
// direct/transitive split.
//
// Both the npm v1 lockfile and every yarn.lock need this, for the same reason —
// neither records the root project's own declarations in a form that can be
// told apart from everything else in the file.
func declaredInPackageJSON(path string) map[string]string {
	data, err := readManifestFile(path)
	if err != nil {
		return nil
	}
	var pkg struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}

	roots := make(map[string]string)
	for _, m := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.OptionalDependencies} {
		for name, constraint := range m {
			roots[name] = constraint
		}
	}
	return roots
}

// resolver answers which installed package a dependency edge points at. The
// two npm lockfile families disagree about this and about nothing else:
// package-lock.json keys packages by where they sit on disk, so an edge is
// resolved by walking node_modules outwards from the dependent, while yarn.lock
// keys them by the requirement they satisfy, so the edge itself is the key. The
// traversal is written once against this.
type resolver func(from, name, constraint string) (string, bool)

// walkGraph breadth-first searches from the declared dependencies, so the route
// recorded for a package is the shortest one that introduces it. That is the
// route worth showing: it answers "why is this in my tree" with the fewest
// hops, and the hop nearest the root is the one a developer can actually
// change.
//
// Packages the search never reaches are still reported, with no route. A
// lockfile can retain entries for a platform the current install skipped, and a
// vulnerability in one of those is not made harmless by the graph edge being
// absent from this file.
func walkGraph(nodes map[string]node, roots map[string]string, resolve resolver, ecosystem, manifest string) []Dependency {
	type queued struct {
		key  string
		path []string
	}

	seen := make(map[string]bool, len(nodes))
	deps := make([]Dependency, 0, len(nodes))
	var queue []queued

	for _, name := range sortedKeys(roots) {
		key, ok := resolve("", name, roots[name])
		if !ok || seen[key] {
			continue
		}
		seen[key] = true
		deps = append(deps, Dependency{
			Name:      nodes[key].name,
			Version:   nodes[key].version,
			Ecosystem: ecosystem,
			File:      manifest,
			Direct:    true,
		})
		queue = append(queue, queued{key: key, path: []string{nodes[key].name}})
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for _, name := range sortedKeys(nodes[current.key].deps) {
			key, ok := resolve(current.key, name, nodes[current.key].deps[name])
			if !ok || seen[key] {
				continue
			}
			seen[key] = true

			// The route is the parent's route; the package itself is the
			// destination, not part of the path leading to it.
			route := make([]string, len(current.path))
			copy(route, current.path)

			deps = append(deps, Dependency{
				Name:      nodes[key].name,
				Version:   nodes[key].version,
				Ecosystem: ecosystem,
				File:      manifest,
				Path:      route,
			})
			queue = append(queue, queued{key: key, path: append(route, nodes[key].name)})
		}
	}

	for _, key := range sortedKeys(nodes) {
		if seen[key] {
			continue
		}
		deps = append(deps, Dependency{
			Name:      nodes[key].name,
			Version:   nodes[key].version,
			Ecosystem: ecosystem,
			File:      manifest,
		})
	}

	return deps
}

// resolveNPM finds which installed package a dependency edge points at, by the
// rule Node itself uses: look inside the dependent's own node_modules first,
// then walk up towards the root, taking the first match. This is what makes
// two versions of the same package resolvable — a nested copy shadows the
// hoisted one for whatever required it.
func resolveNPM(nodes map[string]node, from, name string) (string, bool) {
	prefix := from
	for {
		candidate := "node_modules/" + name
		if prefix != "" {
			candidate = prefix + "/node_modules/" + name
		}
		if _, ok := nodes[candidate]; ok {
			return candidate, true
		}
		// The root's own node_modules is the last place to look, and it is
		// where npm hoists almost everything: a tree with no version conflicts
		// is entirely flat. Stopping before trying it — which is what happens
		// if the walk-up only ever strips "/node_modules/" components — leaves
		// every transitive package unreachable and therefore unattributed.
		if prefix == "" {
			return "", false
		}
		if cut := strings.LastIndex(prefix, "/node_modules/"); cut >= 0 {
			prefix = prefix[:cut]
		} else {
			prefix = ""
		}
	}
}

// ============= yarn =============

// YarnLockParser parses yarn.lock in both of its formats: the bespoke text of
// Yarn 1, and the YAML of Yarn 2 and later ("Berry").
//
// Yarn keys packages by the requirement they satisfy rather than by where they
// land on disk. An entry header is one or more descriptors — "express@^4.17.1",
// or "express@npm:^4.17.1" under Berry — and a dependency edge names exactly
// such a descriptor. That makes resolution a lookup instead of the outward walk
// package-lock.json needs, and it makes it exact: two packages requiring
// different ranges of the same dependency point at different entries with no
// ambiguity to resolve.
//
// What yarn.lock does not record is which packages the project itself asked
// for. Every entry looks alike, whether it is a declared dependency or
// something six levels down. The sibling package.json supplies that; without
// one, every package is still reported and only the direct/transitive split is
// lost.
type YarnLockParser struct{}

func (p *YarnLockParser) Name() string    { return "yarn (lockfile)" }
func (p *YarnLockParser) Files() []string { return []string{"yarn.lock"} }
func (p *YarnLockParser) Lockfile()       {}

func (p *YarnLockParser) Parse(path string) ([]Dependency, error) {
	data, err := readManifestFile(path)
	if err != nil {
		return nil, err
	}

	var nodes map[string]node
	var descriptors map[string]string

	// Berry announces itself with a __metadata block. The two formats are not
	// distinguished by attempting a YAML parse and seeing what happens: Yarn 1
	// output is close enough to YAML to make failure an unreliable signal.
	if bytes.Contains(data, []byte("__metadata:")) {
		nodes, descriptors, err = parseYarnBerry(data)
	} else {
		nodes, descriptors = parseYarnClassic(string(data))
	}
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, nil
	}

	resolve := func(_, name, constraint string) (string, bool) {
		return resolveYarn(descriptors, name, constraint)
	}
	roots := declaredInPackageJSON(filepath.Join(filepath.Dir(path), "package.json"))
	return walkGraph(nodes, roots, resolve, "npm", path), nil
}

// parseYarnClassic reads the Yarn 1 format:
//
//	"@babel/core@^7.0.0", "@babel/core@^7.1.0":
//	  version "7.20.0"
//	  dependencies:
//	    "@babel/types" "^7.20.0"
//
// An entry header sits at column zero and ends in a colon; everything indented
// under it belongs to that entry, and the nested "dependencies" block is
// indented once further.
func parseYarnClassic(content string) (map[string]node, map[string]string) {
	nodes := make(map[string]node)
	descriptors := make(map[string]string)

	var header []string
	var version string
	var deps map[string]string
	inDeps := false

	flush := func() {
		if len(header) == 0 || version == "" {
			return
		}
		name := yarnNameOf(header[0])
		if name == "" {
			return
		}
		key := name + "@" + version
		nodes[key] = node{name: name, version: version, deps: deps}
		for _, descriptor := range header {
			descriptors[descriptor] = key
		}
	}

	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// A new entry begins at column zero.
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			flush()
			header = splitYarnHeader(trimmed)
			version, deps, inDeps = "", nil, false
			continue
		}

		indent := len(line) - len(strings.TrimLeft(line, " \t"))

		switch {
		case trimmed == "dependencies:" || trimmed == "optionalDependencies:":
			inDeps = true
		case strings.HasPrefix(trimmed, "version"):
			version = unquoteYarn(strings.TrimSpace(strings.TrimPrefix(trimmed, "version")))
			inDeps = false
		case inDeps && indent >= 4:
			name, constraint, ok := splitYarnEdge(trimmed)
			if !ok {
				continue
			}
			if deps == nil {
				deps = make(map[string]string)
			}
			deps[name] = constraint
		default:
			// resolved, integrity, checksum and the rest carry nothing this
			// scanner acts on. Any of them ends a dependencies block, because
			// they are indented at the entry's own level.
			if indent <= 2 {
				inDeps = false
			}
		}
	}
	flush()

	return nodes, descriptors
}

// yarnBerryEntry is one entry of a Yarn 2+ lockfile.
type yarnBerryEntry struct {
	Version      string            `yaml:"version"`
	Resolution   string            `yaml:"resolution"`
	LinkType     string            `yaml:"linkType"`
	Dependencies map[string]string `yaml:"dependencies"`
}

func parseYarnBerry(data []byte) (map[string]node, map[string]string, error) {
	var raw map[string]yarnBerryEntry
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, nil, err
	}

	nodes := make(map[string]node, len(raw))
	descriptors := make(map[string]string, len(raw))

	for header, entry := range raw {
		if header == "__metadata" || entry.Version == "" {
			continue
		}
		// A workspace resolution is a directory of this repository, not a
		// published package, and has no version an advisory can be matched
		// against.
		if strings.Contains(entry.Resolution, "@workspace:") {
			continue
		}

		specs := splitYarnHeader(header)
		if len(specs) == 0 {
			continue
		}
		name := yarnNameOf(specs[0])
		if name == "" {
			continue
		}

		key := name + "@" + entry.Version
		nodes[key] = node{name: name, version: entry.Version, deps: entry.Dependencies}
		for _, descriptor := range specs {
			descriptors[descriptor] = key
		}
	}

	return nodes, descriptors, nil
}

// resolveYarn finds the entry satisfying one dependency edge. Berry writes the
// protocol into both descriptors and edges ("npm:^4.17.1"), Yarn 1 writes
// neither, and an edge can be recorded in either style depending on which tool
// last wrote the file — so both spellings are tried before giving up.
func resolveYarn(descriptors map[string]string, name, constraint string) (string, bool) {
	candidates := []string{name + "@" + constraint}
	if after, found := strings.CutPrefix(constraint, "npm:"); found {
		candidates = append(candidates, name+"@"+after)
	} else {
		candidates = append(candidates, name+"@npm:"+constraint)
	}

	for _, candidate := range candidates {
		if key, ok := descriptors[candidate]; ok {
			return key, true
		}
	}
	return "", false
}

// splitYarnHeader breaks an entry header into its descriptors. One entry can
// satisfy several requirements at once, and the header lists them all.
func splitYarnHeader(header string) []string {
	header = strings.TrimSuffix(strings.TrimSpace(header), ":")

	var specs []string
	for _, part := range strings.Split(header, ",") {
		if spec := unquoteYarn(strings.TrimSpace(part)); spec != "" {
			specs = append(specs, spec)
		}
	}
	return specs
}

// yarnNameOf takes the package name out of a descriptor. The separator is the
// last "@" rather than the first, because a scoped name opens with one:
// "@babel/core@^7.0.0" is the package "@babel/core" at "^7.0.0".
func yarnNameOf(descriptor string) string {
	if at := strings.LastIndex(descriptor, "@"); at > 0 {
		return descriptor[:at]
	}
	return descriptor
}

// splitYarnEdge reads one line of a Yarn 1 dependencies block, where the name
// and the range are separated by a space and either may be quoted.
func splitYarnEdge(line string) (string, string, bool) {
	name, constraint, found := strings.Cut(line, " ")
	if !found {
		return "", "", false
	}
	return unquoteYarn(name), unquoteYarn(strings.TrimSpace(constraint)), true
}

func unquoteYarn(s string) string {
	return strings.Trim(strings.TrimSpace(s), `"'`)
}

// ============= composer =============

// ComposerLockParser parses PHP's composer.lock.
//
// Composer resolves to one version of a package for the whole project — there
// is no equivalent of a nested node_modules copy — so a package name is on its
// own a unique key, and an edge resolves by name alone. The constraint the
// dependent wrote is not consulted: the lockfile has already decided which
// version satisfies it, and there is only ever the one.
//
// Like yarn.lock, composer.lock does not record what the root project asked
// for: "packages" and "packages-dev" are flat lists in which a declared
// dependency looks exactly like something six levels down. The sibling
// composer.json supplies that, and without one every package is still reported
// with only the direct/transitive split lost.
type ComposerLockParser struct{}

func (p *ComposerLockParser) Name() string    { return "composer (lockfile)" }
func (p *ComposerLockParser) Files() []string { return []string{"composer.lock"} }
func (p *ComposerLockParser) Lockfile()       {}

// composerLock covers the parts of composer.lock this parser reads. Development
// dependencies live in their own list but are installed into the same flat
// vendor directory, so both are read into one graph.
type composerLock struct {
	Packages    []composerPackage `json:"packages"`
	PackagesDev []composerPackage `json:"packages-dev"`
}

// composerPackage is one entry of either list. The same shape appears in
// vendor/composer/installed.json, which is why both sources share it.
type composerPackage struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Require map[string]string `json:"require"`
}

func (p *ComposerLockParser) Parse(path string) ([]Dependency, error) {
	data, err := readManifestFile(path)
	if err != nil {
		return nil, err
	}

	var lock composerLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	nodes := composerNodes(lock.Packages, lock.PackagesDev)
	if len(nodes) == 0 {
		return nil, nil
	}

	roots := declaredInComposerJSON(filepath.Join(filepath.Dir(path), "composer.json"))
	return walkGraph(nodes, roots, composerResolver(nodes), "packagist", path), nil
}

// composerNodes reduces the lists composer writes into the node map the graph
// walk expects, keyed by package name.
func composerNodes(lists ...[]composerPackage) map[string]node {
	nodes := make(map[string]node)

	for _, list := range lists {
		for _, pkg := range list {
			if pkg.Name == "" || pkg.Version == "" {
				continue
			}

			deps := make(map[string]string, len(pkg.Require))
			for name, constraint := range pkg.Require {
				if !isPackagistName(name) {
					continue
				}
				deps[composerKey(name)] = constraint
			}

			// The version is kept exactly as the lockfile writes it, "v" and
			// all — that is the string a developer will find when they grep the
			// file, and OSV normalises the prefix away before matching.
			nodes[composerKey(pkg.Name)] = node{name: pkg.Name, version: pkg.Version, deps: deps}
		}
	}

	return nodes
}

// composerResolver answers a dependency edge by name, which is all Composer's
// flat installation leaves to do.
//
// An edge that names nothing installed is left unresolved, and the two ways
// that happens are both harmless here. A virtual package — "psr/http-message-
// implementation", which guzzlehttp/psr7 provides rather than being — has no
// entry because no such thing is installed. A replaced package, as when
// symfony/symfony stands in for symfony/http-kernel, has none for the same
// reason. Neither loses a package from the report: everything installed is
// listed regardless, and what is lost at most is one route through the graph.
func composerResolver(nodes map[string]node) resolver {
	return func(_, name, _ string) (string, bool) {
		key := composerKey(name)
		_, ok := nodes[key]
		return key, ok
	}
}

// declaredInComposerJSON reads what the project requires of itself, as name to
// constraint. A missing or unreadable composer.json is not an error: the
// resolved graph is still complete, and only the direct/transitive split is
// lost.
func declaredInComposerJSON(path string) map[string]string {
	data, err := readManifestFile(path)
	if err != nil {
		return nil
	}
	var pkg struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}

	roots := make(map[string]string)
	for _, m := range []map[string]string{pkg.Require, pkg.RequireDev} {
		for name, constraint := range m {
			if !isPackagistName(name) {
				continue
			}
			roots[composerKey(name)] = constraint
		}
	}
	return roots
}

// isPackagistName separates real packages from Composer's platform packages.
//
// A require block mixes the two freely: "php": ">=7.2", "ext-json": "*" and
// "composer-runtime-api": "^2.0" sit alongside "guzzlehttp/psr7": "^1.6". The
// platform entries describe the interpreter and its extensions, not code
// fetched from a registry, and querying an advisory database for a package
// named "php" or "ext-json" returns nothing while making the dependency count
// wrong. Every Packagist package is published as vendor/name, and no platform
// package contains a slash, so the slash is the whole test.
func isPackagistName(name string) bool {
	return strings.Contains(name, "/")
}

// composerKey normalises a package name for lookup. Composer treats names
// case-insensitively — a require block spelling "Monolog/Monolog" installs the
// same package as "monolog/monolog" — so an edge written in either case has to
// find the one node.
func composerKey(name string) string {
	return strings.ToLower(name)
}

// ============= cargo =============

// CargoLockParser parses Rust's Cargo.lock.
//
// Cargo.lock is the only lockfile here that records the root project without
// help: a workspace member or path dependency is written as a package with no
// "source", because it is not fetched from anywhere, and its dependency list
// is exactly what the project asked for. No sibling manifest is needed for the
// direct/transitive split.
//
// Two crates of the same name at different versions coexist routinely — a tree
// holding both time 0.1 and time 0.3 is unremarkable — so a name alone is not a
// key. Cargo writes a dependency edge as a bare name where that is unambiguous
// and as "name version" where it is not, and the parser follows the same rule.
type CargoLockParser struct{}

func (p *CargoLockParser) Name() string    { return "cargo (lockfile)" }
func (p *CargoLockParser) Files() []string { return []string{"Cargo.lock"} }
func (p *CargoLockParser) Lockfile()       {}

// cargoLock covers the parts of Cargo.lock this parser reads. The [metadata]
// table of the older formats holds checksums and nothing else.
type cargoLock struct {
	Package []cargoPackage `toml:"package"`
}

type cargoPackage struct {
	Name         string   `toml:"name"`
	Version      string   `toml:"version"`
	Source       string   `toml:"source"`
	Dependencies []string `toml:"dependencies"`
}

func (p *CargoLockParser) Parse(path string) ([]Dependency, error) {
	data, err := readManifestFile(path)
	if err != nil {
		return nil, err
	}

	var lock cargoLock
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	nodes := make(map[string]node, len(lock.Package))
	roots := make(map[string]string)

	for _, pkg := range lock.Package {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}

		// No source means the crate was not fetched: it is a workspace member
		// or a path dependency, so it is the project's own code rather than a
		// dependency of it. What it requires is what the project requires.
		if pkg.Source == "" {
			for _, descriptor := range pkg.Dependencies {
				roots[descriptor] = ""
			}
			continue
		}

		deps := make(map[string]string, len(pkg.Dependencies))
		for _, descriptor := range pkg.Dependencies {
			deps[descriptor] = ""
		}
		nodes[cargoKey(pkg.Name, pkg.Version)] = node{name: pkg.Name, version: pkg.Version, deps: deps}
	}

	if len(nodes) == 0 {
		return nil, nil
	}
	return walkGraph(nodes, roots, cargoResolver(nodes), "cargo", path), nil
}

// cargoResolver answers a dependency edge written in any of the three spellings
// Cargo has used: "libc", "time 0.1.45", and the older "time 0.1.45
// (registry+https://github.com/rust-lang/crates.io-index)".
//
// Where the edge carries no version, Cargo has guaranteed the name is unique in
// the tree. If it turns out not to be, the edge is left unresolved rather than
// guessed at: attaching a route to the wrong copy of a crate would tell a
// reader to change a dependency that does not lead there.
func cargoResolver(nodes map[string]node) resolver {
	byName := make(map[string][]string, len(nodes))
	for key, n := range nodes {
		byName[n.name] = append(byName[n.name], key)
	}

	return func(_, descriptor, _ string) (string, bool) {
		name, version := splitCargoDescriptor(descriptor)
		if version != "" {
			key := cargoKey(name, version)
			_, ok := nodes[key]
			return key, ok
		}
		if keys := byName[name]; len(keys) == 1 {
			return keys[0], true
		}
		return "", false
	}
}

// splitCargoDescriptor takes the name and, where one is written, the version
// out of a dependency edge. A version can carry build metadata —
// "0.11.1+wasi-snapshot-preview1" — which holds no space and so survives the
// split intact.
func splitCargoDescriptor(descriptor string) (name, version string) {
	fields := strings.Fields(descriptor)
	if len(fields) == 0 {
		return "", ""
	}
	if len(fields) > 1 && !strings.HasPrefix(fields[1], "(") {
		return fields[0], fields[1]
	}
	return fields[0], ""
}

func cargoKey(name, version string) string {
	return name + " " + version
}

// CargoTOMLParser parses Rust's Cargo.toml, the last resort for a crate that
// does not commit its lockfile — normal for a library, since Cargo.lock is
// ignored for anything consumed as a dependency.
type CargoTOMLParser struct{}

func (p *CargoTOMLParser) Name() string    { return "cargo" }
func (p *CargoTOMLParser) Files() []string { return []string{"Cargo.toml"} }

func (p *CargoTOMLParser) Parse(path string) ([]Dependency, error) {
	data, err := readManifestFile(path)
	if err != nil {
		return nil, err
	}

	var manifest struct {
		Dependencies      map[string]any `toml:"dependencies"`
		DevDependencies   map[string]any `toml:"dev-dependencies"`
		BuildDependencies map[string]any `toml:"build-dependencies"`
	}
	if err := toml.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}

	var deps []Dependency
	for _, table := range []map[string]any{manifest.Dependencies, manifest.DevDependencies, manifest.BuildDependencies} {
		for _, name := range sortedKeys(table) {
			version, pinned, ok := cargoDeclaredVersion(table[name])
			if !ok {
				continue
			}
			deps = append(deps, Dependency{
				Name:           name,
				Version:        version,
				VersionIsRange: !pinned,
				Ecosystem:      "cargo",
				File:           path,
			})
		}
	}
	return deps, nil
}

// cargoDeclaredVersion reads the version out of a Cargo.toml dependency entry,
// which is either the range on its own — serde = "1.0" — or a table carrying it
// alongside features and the rest.
//
// An entry with no version of its own is dropped rather than reported at the
// empty string. A git or path dependency has none, and one inheriting from the
// workspace — serde = { workspace = true } — keeps it in the root manifest. A
// dependency reported without a version matches every advisory for that crate
// or none, depending on the database's mood, and neither answer is worth
// giving.
// Cargo is the ecosystem where a bare version is *not* a pin: `serde = "1.0"`
// is shorthand for `^1.0`, and only `=1.0.130` names a single release. Passing
// false here is the whole difference from every other manifest.
func cargoDeclaredVersion(entry any) (version string, pinned, found bool) {
	switch v := entry.(type) {
	case string:
		version, pinned = pinnedVersion(v, false)
		return version, pinned, true
	case map[string]any:
		if spec, ok := v["version"].(string); ok {
			version, pinned = pinnedVersion(spec, false)
			return version, pinned, true
		}
	}
	return "", false, false
}

// ============= poetry =============

// PoetryLockParser parses Python's poetry.lock.
//
// Python installs one version of a distribution per environment — site-packages
// has a single directory per project name — so a name is a unique key, as it is
// for Composer. What Python adds is that the *same* name is written several
// ways: jinja2 requires "MarkupSafe" while the package that satisfies it is
// locked as "markupsafe". PEP 503 defines the normal form both reduce to, and
// resolving edges without it silently loses the route for every package whose
// requirement was spelled differently from its own metadata.
//
// A dependency edge's value is ignored entirely. Poetry writes it as a
// constraint string, or a table carrying environment markers, or an array of
// those for a package constrained differently per platform — but the lockfile
// has already chosen the one version, so the only thing the edge has to say is
// which package it points at.
type PoetryLockParser struct{}

func (p *PoetryLockParser) Name() string    { return "poetry (lockfile)" }
func (p *PoetryLockParser) Files() []string { return []string{"poetry.lock"} }
func (p *PoetryLockParser) Lockfile()       {}

// poetryLock covers the parts of poetry.lock this parser reads. The
// [package.extras] table beside [package.dependencies] is deliberately absent:
// an extra is a dependency the project has to ask for by name, and `poetry
// install` without --extras does not install it.
type poetryLock struct {
	Package []poetryPackage `toml:"package"`
}

type poetryPackage struct {
	Name         string         `toml:"name"`
	Version      string         `toml:"version"`
	Dependencies map[string]any `toml:"dependencies"`
}

func (p *PoetryLockParser) Parse(path string) ([]Dependency, error) {
	data, err := readManifestFile(path)
	if err != nil {
		return nil, err
	}

	var lock poetryLock
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	nodes := make(map[string]node, len(lock.Package))
	for _, pkg := range lock.Package {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		deps := make(map[string]string, len(pkg.Dependencies))
		for name := range pkg.Dependencies {
			deps[normalizePythonName(name)] = ""
		}
		nodes[normalizePythonName(pkg.Name)] = node{name: pkg.Name, version: pkg.Version, deps: deps}
	}

	if len(nodes) == 0 {
		return nil, nil
	}

	roots := declaredInPyProject(filepath.Join(filepath.Dir(path), "pyproject.toml"))
	return walkGraph(nodes, roots, pythonResolver(nodes), "pypi", path), nil
}

// pythonResolver answers a dependency edge by normalised name, which is all a
// single-version-per-environment installation leaves to do.
func pythonResolver(nodes map[string]node) resolver {
	return func(_, name, _ string) (string, bool) {
		key := normalizePythonName(name)
		_, ok := nodes[key]
		return key, ok
	}
}

// declaredInPyProject reads what the project requires of itself.
//
// Two layouts have to be read, and a modern Poetry project can use either or
// both: the PEP 621 [project] table, whose "dependencies" is a list of
// requirement strings, and Poetry's own [tool.poetry.dependencies] plus the
// per-group tables under [tool.poetry.group]. Development groups are included —
// they are installed, they run in CI, and a flaw in one is real.
//
// A missing or unreadable pyproject.toml is not an error: the resolved graph is
// still complete, and only the direct/transitive split is lost.
func declaredInPyProject(path string) map[string]string {
	// Deliberately the same reader the manifest tier uses. pyproject.toml has
	// four places a dependency can be declared, and two readers of it drifted
	// apart the moment one learned about [dependency-groups] and the other did
	// not — which cost the packages in that group their direct flag, and
	// everything below them its route.
	deps, err := (&PyProjectParser{}).Parse(path)
	if err != nil {
		return nil
	}

	roots := make(map[string]string, len(deps))
	for _, dep := range deps {
		roots[normalizePythonName(dep.Name)] = ""
	}
	return roots
}

// requirementName takes the distribution name out of a PEP 508 requirement
// string — "requests[socks] >= 2.27.0 ; python_version >= '3'" is a requirement
// on "requests". Everything from the first character that cannot appear in a
// name onwards is the extras list, the constraint, or the marker.
func requirementName(requirement string) string {
	name := strings.TrimSpace(requirement)
	if cut := strings.IndexAny(name, "[<>=!~; ("); cut >= 0 {
		name = name[:cut]
	}
	return strings.TrimSpace(name)
}

// declaredInRequirements reads the names out of a requirements.txt, for the
// case where it is the only manifest a project has.
func declaredInRequirements(path string) map[string]string {
	deps, err := (&RequirementsTXTParser{}).Parse(path)
	if err != nil {
		return nil
	}
	roots := make(map[string]string, len(deps))
	for _, dep := range deps {
		roots[normalizePythonName(dep.Name)] = ""
	}
	return roots
}

// PyProjectParser parses pyproject.toml, Python's manifest.
//
// It is the last resort for a project with no lockfile — which in Python is a
// common shape rather than an oversight, since pip writes none. Its entries are
// requirements rather than resolutions, so most of them are ranges and are
// reported as inventory without being matched; see pinnedVersion.
type PyProjectParser struct{}

func (p *PyProjectParser) Name() string    { return "python" }
func (p *PyProjectParser) Files() []string { return []string{"pyproject.toml"} }

func (p *PyProjectParser) Parse(path string) ([]Dependency, error) {
	data, err := readManifestFile(path)
	if err != nil {
		return nil, err
	}

	var manifest struct {
		Project struct {
			Dependencies         []string            `toml:"dependencies"`
			OptionalDependencies map[string][]string `toml:"optional-dependencies"`
		} `toml:"project"`
		DependencyGroups map[string][]string `toml:"dependency-groups"`
		Tool             struct {
			Poetry struct {
				Dependencies map[string]any `toml:"dependencies"`
				Group        map[string]struct {
					Dependencies map[string]any `toml:"dependencies"`
				} `toml:"group"`
			} `toml:"poetry"`
		} `toml:"tool"`
	}
	if err := toml.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var deps []Dependency
	add := func(name, spec string) {
		key := normalizePythonName(name)
		// The interpreter is not a distribution, and Poetry lists it beside the
		// real dependencies.
		if key == "" || key == "python" || seen[key] {
			return
		}
		seen[key] = true

		version, pinned := pinnedVersion(spec, true)
		deps = append(deps, Dependency{
			Name:           name,
			Version:        version,
			VersionIsRange: !pinned,
			Ecosystem:      "pypi",
			File:           path,
		})
	}

	// PEP 621, and the dependency-groups table that uv and pip use for
	// development dependencies.
	requirementLists := [][]string{manifest.Project.Dependencies}
	for _, group := range manifest.Project.OptionalDependencies {
		requirementLists = append(requirementLists, group)
	}
	for _, group := range manifest.DependencyGroups {
		requirementLists = append(requirementLists, group)
	}
	for _, list := range requirementLists {
		for _, requirement := range list {
			name, spec := splitRequirement(requirement)
			add(name, spec)
		}
	}

	// Poetry's own tables, which a project can use instead of or alongside
	// [project].
	poetryTables := []map[string]any{manifest.Tool.Poetry.Dependencies}
	for _, group := range manifest.Tool.Poetry.Group {
		poetryTables = append(poetryTables, group.Dependencies)
	}
	for _, table := range poetryTables {
		for _, name := range sortedKeys(table) {
			switch v := table[name].(type) {
			case string:
				add(name, v)
			case map[string]any:
				spec, _ := v["version"].(string)
				add(name, spec)
			}
		}
	}

	return deps, nil
}

// splitRequirement breaks a PEP 508 requirement into its distribution name and
// its version specifier, dropping the extras list and the environment marker
// that can sit on either side of them.
func splitRequirement(requirement string) (name, spec string) {
	requirement, _, _ = strings.Cut(requirement, ";")
	name = requirementName(requirement)

	spec = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(requirement), name))
	// An extras list belongs to the name, not to the version: the specifier of
	// "requests[socks] >= 2.27.0" starts after the closing bracket.
	if strings.HasPrefix(spec, "[") {
		if close := strings.Index(spec, "]"); close >= 0 {
			spec = strings.TrimSpace(spec[close+1:])
		}
	}
	return name, spec
}

// normalizePythonName reduces a distribution name to the form PEP 503 defines
// for comparison: lower case, with every run of "-", "_" and "." collapsed to a
// single "-". "Flask_SQLAlchemy", "flask-sqlalchemy" and "Flask.SQLAlchemy" are
// one project, and the index treats them as such.
func normalizePythonName(name string) string {
	var b strings.Builder
	b.Grow(len(name))

	previousSeparator := false
	for _, r := range strings.TrimSpace(name) {
		if r == '-' || r == '_' || r == '.' {
			// A leading run is dropped rather than turned into a "-", so a
			// malformed name cannot produce a key that matches nothing.
			if b.Len() > 0 {
				previousSeparator = true
			}
			continue
		}
		if previousSeparator {
			b.WriteByte('-')
			previousSeparator = false
		}
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ============= pipenv =============

// PipfileLockParser parses Pipenv's Pipfile.lock.
//
// It is the one lockfile here that records no graph at all: "default" and
// "develop" are flat maps of name to resolved version, with nothing saying
// which package asked for which. So this tier buys the transitive *set* at
// exact versions — the part that decides whether an advisory matches — and not
// the routes. A finding in a package the project never named will say so, and
// stop there.
//
// The direct set still comes from the sibling Pipfile, which is where the
// project's own [packages] and [dev-packages] are declared.
type PipfileLockParser struct{}

func (p *PipfileLockParser) Name() string    { return "pipenv (lockfile)" }
func (p *PipfileLockParser) Files() []string { return []string{"Pipfile.lock"} }
func (p *PipfileLockParser) Lockfile()       {}

// pipfileEntry is one locked package. A package installed from version control
// or a local path carries "git" or "path" instead of a version, and there is
// nothing for an advisory to match against.
type pipfileEntry struct {
	Version string `json:"version"`
}

func (p *PipfileLockParser) Parse(path string) ([]Dependency, error) {
	data, err := readManifestFile(path)
	if err != nil {
		return nil, err
	}

	var lock struct {
		Default map[string]pipfileEntry `json:"default"`
		Develop map[string]pipfileEntry `json:"develop"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	if len(lock.Default)+len(lock.Develop) == 0 {
		return nil, nil
	}

	// Development packages are installed into the same environment as the
	// rest, so both maps contribute. A name in both is one installation.
	roots := declaredInPipfile(filepath.Join(filepath.Dir(path), "Pipfile"))
	seen := make(map[string]bool, len(lock.Default)+len(lock.Develop))
	deps := make([]Dependency, 0, len(lock.Default)+len(lock.Develop))

	for _, group := range []map[string]pipfileEntry{lock.Default, lock.Develop} {
		for _, name := range sortedKeys(group) {
			key := normalizePythonName(name)
			if seen[key] {
				continue
			}
			seen[key] = true

			// Pipenv writes the resolved version as "==3.12.1". Anything else
			// — "*", or nothing at all for a VCS entry — is not a version, and
			// pinnedVersion reports it as such so it is left unmatched.
			version, pinned := pinnedVersion(group[name].Version, true)
			_, direct := roots[key]
			deps = append(deps, Dependency{
				Name:           name,
				Version:        version,
				VersionIsRange: !pinned,
				Ecosystem:      "pypi",
				File:           path,
				Direct:         direct,
			})
		}
	}
	return deps, nil
}

// declaredInPipfile reads [packages] and [dev-packages] from a Pipfile. Its
// absence costs only the direct/transitive split.
func declaredInPipfile(path string) map[string]string {
	data, err := readManifestFile(path)
	if err != nil {
		return nil
	}
	var manifest struct {
		Packages    map[string]any `toml:"packages"`
		DevPackages map[string]any `toml:"dev-packages"`
	}
	if err := toml.Unmarshal(data, &manifest); err != nil {
		return nil
	}

	roots := make(map[string]string)
	for _, group := range []map[string]any{manifest.Packages, manifest.DevPackages} {
		for name := range group {
			roots[normalizePythonName(name)] = ""
		}
	}
	return roots
}

// ============= uv =============

// UVLockParser parses uv.lock.
//
// uv records the graph the way Cargo does, and marks the root the same way: the
// project itself is a package whose source is "virtual" or "editable" rather
// than a registry, and its dependency list — together with the per-group
// dev-dependencies beside it — is the direct set. No sibling manifest needed.
type UVLockParser struct{}

func (p *UVLockParser) Name() string    { return "uv (lockfile)" }
func (p *UVLockParser) Files() []string { return []string{"uv.lock"} }
func (p *UVLockParser) Lockfile()       {}

type uvLock struct {
	Package []uvPackage `toml:"package"`
}

type uvPackage struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
	// Source distinguishes a package fetched from an index from the project
	// itself. Its single key is the kind: "registry", "virtual", "editable",
	// "directory", "git".
	Source map[string]any `toml:"source"`
	// Dependencies entries are inline tables carrying at least a name, and a
	// version too where the lock holds the same name more than once.
	Dependencies    []uvRef            `toml:"dependencies"`
	DevDependencies map[string][]uvRef `toml:"dev-dependencies"`
}

type uvRef struct {
	Name string `toml:"name"`
}

func (p *UVLockParser) Parse(path string) ([]Dependency, error) {
	data, err := readManifestFile(path)
	if err != nil {
		return nil, err
	}

	var lock uvLock
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	nodes := make(map[string]node, len(lock.Package))
	roots := make(map[string]string)

	for _, pkg := range lock.Package {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}

		edges := make(map[string]string, len(pkg.Dependencies))
		for _, ref := range pkg.Dependencies {
			edges[normalizePythonName(ref.Name)] = ""
		}
		for _, group := range pkg.DevDependencies {
			for _, ref := range group {
				edges[normalizePythonName(ref.Name)] = ""
			}
		}

		// A package that was not fetched from an index is the project, or one
		// of its workspace members: its own code, and what it requires is what
		// the project requires.
		if !uvFromRegistry(pkg.Source) {
			for name := range edges {
				roots[name] = ""
			}
			continue
		}
		nodes[normalizePythonName(pkg.Name)] = node{name: pkg.Name, version: pkg.Version, deps: edges}
	}

	if len(nodes) == 0 {
		return nil, nil
	}
	return walkGraph(nodes, roots, pythonResolver(nodes), "pypi", path), nil
}

// uvFromRegistry reports whether a package was fetched from a package index,
// which is what separates a dependency from the project depending on it.
func uvFromRegistry(source map[string]any) bool {
	_, registry := source["registry"]
	return registry
}

// npmNameFromKey recovers a package name from its installation path. Splitting
// on the last "node_modules/" keeps scoped names intact: the "/" inside
// "@scope/pkg" is not a path separator here.
func npmNameFromKey(key string) string {
	if i := strings.LastIndex(key, "node_modules/"); i >= 0 {
		return key[i+len("node_modules/"):]
	}
	return key
}

// sortedKeys keeps the traversal deterministic. Go randomises map iteration,
// and without an order the reported route for a package reachable by several
// equally short paths would differ between runs of the same scan.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
