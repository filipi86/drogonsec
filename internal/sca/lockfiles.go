package sca

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
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

	return walkNPMGraph(nodes, roots, path), nil
}

// normaliseNPMLock reduces either lockfile layout to the common node map, and
// returns the names the root project declares for itself.
func normaliseNPMLock(lock *packageLock, path string) (map[string]node, []string) {
	if len(lock.Packages) > 0 {
		return normaliseV3(lock)
	}
	return normaliseV1(lock, path)
}

func normaliseV3(lock *packageLock) (map[string]node, []string) {
	nodes := make(map[string]node, len(lock.Packages))
	var roots []string

	for key, entry := range lock.Packages {
		// The empty key is the project itself: it holds no version of interest,
		// only the list of what the project actually asked for. That list is
		// the sole way to tell a direct dependency from a transitive one that
		// npm hoisted to the top of node_modules alongside it.
		if key == "" {
			roots = append(roots, mapKeys(entry.Dependencies)...)
			roots = append(roots, mapKeys(entry.DevDependencies)...)
			roots = append(roots, mapKeys(entry.OptionalDependencies)...)
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

	sort.Strings(roots)
	return nodes, roots
}

// normaliseV1 flattens the nested v1 tree into the same path-keyed map the v3
// layout already uses, so one traversal serves both. A v1 lockfile does not
// record what the project declared, so the sibling package.json is consulted
// for that; without it every package is reported, but none can be called
// direct.
func normaliseV1(lock *packageLock, path string) (map[string]node, []string) {
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

	return nodes, npmRootsFromPackageJSON(filepath.Join(filepath.Dir(path), "package.json"))
}

// npmRootsFromPackageJSON reads the names the project declares. A missing or
// unreadable package.json is not an error: the lockfile still describes every
// installed package, and the only thing lost is the direct/transitive split.
func npmRootsFromPackageJSON(path string) []string {
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
	roots := append(mapKeys(pkg.Dependencies), mapKeys(pkg.DevDependencies)...)
	roots = append(roots, mapKeys(pkg.OptionalDependencies)...)
	sort.Strings(roots)
	return roots
}

// walkNPMGraph breadth-first searches from the declared dependencies, so the
// route recorded for a package is the shortest one that introduces it. That is
// the route worth showing: it answers "why is this in my tree" with the fewest
// hops, and it is the hop nearest the root that a developer can actually
// change.
//
// Packages the search never reaches are still reported, with no route. A lock
// file can retain entries for a platform the current install skipped, and a
// vulnerability in one of those is not made harmless by the graph edge being
// absent from this file.
func walkNPMGraph(nodes map[string]node, roots []string, manifest string) []Dependency {
	type queued struct {
		key  string
		path []string
	}

	seen := make(map[string]bool, len(nodes))
	deps := make([]Dependency, 0, len(nodes))
	var queue []queued

	for _, name := range roots {
		if key, ok := resolveNPM(nodes, "", name); ok && !seen[key] {
			seen[key] = true
			deps = append(deps, Dependency{
				Name:      nodes[key].name,
				Version:   nodes[key].version,
				Ecosystem: "npm",
				File:      manifest,
				Direct:    true,
			})
			queue = append(queue, queued{key: key, path: []string{nodes[key].name}})
		}
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for _, name := range sortedKeys(nodes[current.key].deps) {
			key, ok := resolveNPM(nodes, current.key, name)
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
				Ecosystem: "npm",
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
			Ecosystem: "npm",
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

// npmNameFromKey recovers a package name from its installation path. Splitting
// on the last "node_modules/" keeps scoped names intact: the "/" inside
// "@scope/pkg" is not a path separator here.
func npmNameFromKey(key string) string {
	if i := strings.LastIndex(key, "node_modules/"); i >= 0 {
		return key[i+len("node_modules/"):]
	}
	return key
}

func mapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
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
