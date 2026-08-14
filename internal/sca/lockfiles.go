package sca

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"

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
