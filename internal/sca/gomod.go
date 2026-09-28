package sca

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ============= go =============

// GoModParser parses Go's go.mod.
//
// go.mod is the manifest and, since Go 1.17, most of a lockfile too. A module
// declaring go 1.17 or later lists every module that provides a package to its
// build, direct and indirect, each at the version minimal version selection
// settled on — the "// indirect" block `go mod tidy` maintains. That is the
// full set of third-party code that compiles into the binary, which is the
// question a scan is asking. go.sum is not needed and not read: it holds
// checksums for more versions than are selected, and says nothing about which
// one was.
//
// A go.mod older than 1.17 lists only the direct requirements and whichever
// indirect ones happened to need recording, so for those the set is what the
// file records and no more. `go mod tidy -go=1.17` brings it up to date.
//
// What go.mod does not hold is edges. Each module's own go.mod does, and the Go
// toolchain keeps those in the module cache as
// cache/download/<module>/@v/<version>.mod the moment it resolves the graph —
// before anything is built. They are immutable and checked against go.sum, so
// reading them is reading the same inputs the selection was made from. Where
// the cache is absent every module is still reported, direct ones marked, and
// only the routes are lost.
type GoModParser struct{}

func (p *GoModParser) Name() string    { return "go" }
func (p *GoModParser) Files() []string { return []string{"go.mod"} }
func (p *GoModParser) Lockfile()       {}

func (p *GoModParser) Parse(path string) ([]Dependency, error) {
	data, err := readManifestFile(path)
	if err != nil {
		return nil, err
	}
	mod := parseGoMod(string(data))

	nodes := make(map[string]node, len(mod.require))
	roots := make(map[string]string)
	cache := goModCacheDir()

	for _, req := range mod.require {
		name, version := req.path, req.version

		// A replacement decides what is built. One pointing at a directory
		// is the project's own code — a fork kept in the repository, a
		// sibling module of a workspace — and has no registry version to
		// check. One pointing at another module is that module, at that
		// version, and it is what an advisory has to be matched against.
		if rep, ok := mod.replacementFor(req.path, req.version); ok {
			if rep.local {
				continue
			}
			name, version = rep.path, rep.version
		}

		var deps map[string]string
		if cache != "" && safeModulePath(name) && safePathSegment(version) {
			deps = goModRequirements(filepath.Join(cache, "cache", "download", escapeModulePath(name), "@v", escapeModulePath(version)+".mod"))
		}
		// Nodes are keyed by the path the rest of the graph uses to name the
		// module, which is the original one: a dependency's go.mod requires
		// github.com/foo/bar, never the fork it was replaced with.
		nodes[req.path] = node{name: name, version: version, deps: deps}
		if !req.indirect {
			roots[req.path] = ""
		}
	}

	if len(nodes) == 0 {
		return nil, nil
	}

	// Minimal version selection keeps one version of each module path, so an
	// edge resolves by path. An edge to a module absent from go.mod points at
	// something graph pruning left out of the build — typically a dependency
	// of a dependency's tests — and is correctly left unresolved.
	resolve := func(_, name, _ string) (string, bool) {
		_, ok := nodes[name]
		return name, ok
	}
	return walkGraph(nodes, roots, resolve, "go", path), nil
}

// goMod is the part of a go.mod file the scanner reads.
type goMod struct {
	require []goRequire
	replace []goReplace
}

type goRequire struct {
	path, version string
	indirect      bool
}

type goReplace struct {
	// oldVersion is empty when the replacement applies to every version.
	oldPath, oldVersion string
	path, version       string
	local               bool
}

// replacementFor finds the replace directive that applies to one requirement.
// A directive naming a version applies to that version only and wins over one
// naming none, which is Go's own rule.
func (m goMod) replacementFor(path, version string) (goReplace, bool) {
	var fallback *goReplace
	for i, rep := range m.replace {
		if rep.oldPath != path {
			continue
		}
		if rep.oldVersion == version {
			return rep, true
		}
		if rep.oldVersion == "" {
			fallback = &m.replace[i]
		}
	}
	if fallback != nil {
		return *fallback, true
	}
	return goReplace{}, false
}

// parseGoMod reads require and replace directives, in both their single-line
// and block forms. Every other directive — module, go, toolchain, exclude,
// retract, godebug, tool — is skipped: none of them changes which modules are
// built or at which version, exclude included, since `go mod tidy` has already
// recorded the version selection settled on after applying it.
func parseGoMod(content string) goMod {
	var mod goMod
	block := ""

	for _, raw := range strings.Split(content, "\n") {
		line, comment, _ := strings.Cut(raw, "//")
		line = strings.TrimSpace(line)
		indirect := strings.TrimSpace(comment) == "indirect" || strings.HasPrefix(strings.TrimSpace(comment), "indirect;")

		if line == "" {
			continue
		}
		if block != "" {
			if line == ")" {
				block = ""
				continue
			}
			mod.add(block, line, indirect)
			continue
		}

		verb, rest, _ := strings.Cut(line, " ")
		rest = strings.TrimSpace(rest)
		if rest == "(" {
			block = verb
			continue
		}
		mod.add(verb, rest, indirect)
	}
	return mod
}

func (m *goMod) add(verb, args string, indirect bool) {
	fields := goModFields(args)
	switch verb {
	case "require":
		if len(fields) == 2 {
			m.require = append(m.require, goRequire{path: fields[0], version: fields[1], indirect: indirect})
		}
	case "replace":
		arrow := -1
		for i, f := range fields {
			if f == "=>" {
				arrow = i
			}
		}
		if arrow < 1 || arrow == len(fields)-1 {
			return
		}
		rep := goReplace{oldPath: fields[0]}
		if arrow == 2 {
			rep.oldVersion = fields[1]
		}
		target := fields[arrow+1:]
		rep.path = target[0]
		switch {
		case len(target) == 2:
			rep.version = target[1]
		case len(target) == 1:
			// A replacement without a version must be a directory, which
			// Go recognises by its leading ./, ../ or /.
			rep.local = true
		default:
			return
		}
		m.replace = append(m.replace, rep)
	}
}

// goModFields splits a directive's arguments, unquoting the rare module path
// or version written as a Go string literal.
func goModFields(args string) []string {
	fields := strings.Fields(args)
	for i, f := range fields {
		if strings.HasPrefix(f, `"`) || strings.HasPrefix(f, "`") {
			if unquoted, err := strconv.Unquote(f); err == nil {
				fields[i] = unquoted
			}
		}
	}
	return fields
}

// goModRequirements reads the module paths a cached go.mod requires. Its
// replace directives are ignored because Go ignores them: only the main
// module's replacements apply to a build.
func goModRequirements(path string) map[string]string {
	data, err := readManifestFile(path)
	if err != nil {
		return nil
	}
	mod := parseGoMod(string(data))
	deps := make(map[string]string, len(mod.require))
	for _, req := range mod.require {
		deps[req.path] = req.version
	}
	return deps
}

// goModCacheDir is where the Go toolchain keeps the module cache: GOMODCACHE
// when set, otherwise pkg/mod under the first GOPATH entry, otherwise under
// the default GOPATH of ~/go.
func goModCacheDir() string {
	if dir := os.Getenv("GOMODCACHE"); dir != "" {
		return dir
	}
	if gopath := os.Getenv("GOPATH"); gopath != "" {
		return filepath.Join(filepath.SplitList(gopath)[0], "pkg", "mod")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "go", "pkg", "mod")
}

// safeModulePath reports whether a module path read from go.mod can be joined
// onto the module cache without leaving it. Go itself rejects a path with a
// ".." element or a backslash, so a go.mod holding one — written to probe the
// scanner rather than to build — loses its routes and nothing else.
func safeModulePath(path string) bool {
	if path == "" || strings.Contains(path, `\`) || strings.HasPrefix(path, "/") {
		return false
	}
	for _, element := range strings.Split(path, "/") {
		if element == "" || element == "." || element == ".." {
			return false
		}
	}
	return true
}

// safePathSegment reports whether a value read from a manifest — a version,
// usually — can stand as one directory or file name.
func safePathSegment(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, `/\`)
}

// escapeModulePath applies the module cache's case encoding, under which every
// upper-case letter is written as "!" and its lower-case form, so that
// github.com/BurntSushi/toml and github.com/burntsushi/toml cannot collide on
// a case-insensitive file system.
func escapeModulePath(path string) string {
	var sb strings.Builder
	for _, r := range path {
		if r >= 'A' && r <= 'Z' {
			sb.WriteByte('!')
			sb.WriteRune(r + ('a' - 'A'))
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
