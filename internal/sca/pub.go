package sca

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// ============= pub =============

// PubspecLockParser parses Dart's pubspec.lock.
//
// pub resolves one version of a package for the whole application, like
// Composer, so a name is a unique key and an edge resolves by name alone. The
// lockfile records every package in the solve at the version selected, and —
// unlike yarn.lock or composer.lock — it also says for each one whether the
// project declared it: "direct main", "direct dev", "direct overridden" or
// "transitive". No sibling manifest is needed for the direct/transitive split.
//
// What pubspec.lock does not record is the edges. Those live in each package's
// own pubspec.yaml, which pub has already downloaded into its cache by the
// time the lockfile exists. The cache is read for them where it is present; a
// hosted package in it is immutable — pub keys the directory by name and
// version and checks it against the sha256 in the lockfile — so reading it is
// reading the same data the lockfile was solved from, not one machine's
// passing state. Without the cache every package is still reported, with the
// direct ones marked, and only the routes are lost.
type PubspecLockParser struct{}

func (p *PubspecLockParser) Name() string    { return "pub (lockfile)" }
func (p *PubspecLockParser) Files() []string { return []string{"pubspec.lock"} }
func (p *PubspecLockParser) Lockfile()       {}

type pubspecLock struct {
	Packages map[string]pubLockEntry `yaml:"packages"`
}

type pubLockEntry struct {
	Dependency  string `yaml:"dependency"`
	Source      string `yaml:"source"`
	Version     string `yaml:"version"`
	Description any    `yaml:"description"`
}

func (p *PubspecLockParser) Parse(path string) ([]Dependency, error) {
	data, err := readManifestFile(path)
	if err != nil {
		return nil, err
	}

	var lock pubspecLock
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	projectDir := filepath.Dir(path)
	locations := pubPackageLocations(projectDir)

	nodes := make(map[string]node, len(lock.Packages))
	roots := make(map[string]string)

	for _, name := range sortedKeys(lock.Packages) {
		entry := lock.Packages[name]

		// A path package is code in the repository, a workspace member or a
		// local plugin, not something fetched from a registry: it has no
		// advisories of its own, but what it requires the project requires.
		if entry.Source == "path" {
			if dir := pubPathDescription(entry.Description, projectDir); dir != "" {
				for dep := range pubspecDependencies(filepath.Join(dir, "pubspec.yaml")) {
					roots[dep] = ""
				}
			}
			continue
		}

		// Only hosted packages carry a version a registry advisory can name.
		// "sdk" is Flutter itself and its bundled packages, versioned with the
		// SDK; "git" is a checkout at a commit, where the version in its
		// pubspec says nothing about which fixes it contains.
		if entry.Source != "hosted" || entry.Version == "" {
			continue
		}

		if strings.HasPrefix(entry.Dependency, "direct") {
			roots[name] = ""
		}

		dir := locations[name]
		if dir == "" && pubPackageName.MatchString(name) {
			dir = pubCachedPackageDir(entry, name)
		}
		var deps map[string]string
		if dir != "" {
			deps = pubspecDependencies(filepath.Join(dir, "pubspec.yaml"))
		}
		nodes[name] = node{name: name, version: entry.Version, deps: deps}
	}

	if len(nodes) == 0 {
		return nil, nil
	}

	resolve := func(_, name, _ string) (string, bool) {
		_, ok := nodes[name]
		return name, ok
	}
	return walkGraph(nodes, roots, resolve, "pub", path), nil
}

// pubspecDependencies reads the names a package's pubspec.yaml depends on.
// Only "dependencies" is read: a package's dev_dependencies are what its own
// authors test with, and pub never installs them for a consumer.
func pubspecDependencies(path string) map[string]string {
	data, err := readManifestFile(path)
	if err != nil {
		return nil
	}
	var pubspec struct {
		Dependencies map[string]any `yaml:"dependencies"`
	}
	if err := yaml.Unmarshal(data, &pubspec); err != nil {
		return nil
	}
	deps := make(map[string]string, len(pubspec.Dependencies))
	for name := range pubspec.Dependencies {
		deps[name] = ""
	}
	return deps
}

// pubPackageLocations reads .dart_tool/package_config.json, which pub writes
// beside every lockfile and which names the directory each package was
// resolved to. It is the exact answer to where a package's pubspec lives,
// including for a cache kept somewhere unusual, so it is preferred over
// working the location out.
func pubPackageLocations(projectDir string) map[string]string {
	configDir := filepath.Join(projectDir, ".dart_tool")
	data, err := readManifestFile(filepath.Join(configDir, "package_config.json"))
	if err != nil {
		return nil
	}
	var config struct {
		Packages []struct {
			Name    string `json:"name"`
			RootURI string `json:"rootUri"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil
	}

	locations := make(map[string]string, len(config.Packages))
	for _, pkg := range config.Packages {
		if dir := pubRootDir(pkg.RootURI, configDir); dir != "" {
			locations[pkg.Name] = dir
		}
	}
	return locations
}

// pubRootDir turns a package_config rootUri into a directory. The URI is
// either absolute, file:///home/me/.pub-cache/hosted/pub.dev/http-1.2.0/, or
// relative to the .dart_tool directory holding the file, as for a path
// dependency: "../packages/shared/".
func pubRootDir(rootURI, configDir string) string {
	u, err := url.Parse(rootURI)
	if err != nil {
		return ""
	}
	switch {
	case u.Scheme == "file":
		return filepath.FromSlash(u.Path)
	case u.Scheme == "" && u.Path != "":
		return filepath.Join(configDir, filepath.FromSlash(u.Path))
	}
	return ""
}

// pubPackageName is the shape pub allows a package name, which is also what
// keeps a name read from a lockfile from walking out of the cache directory
// it is joined onto.
var pubPackageName = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

// pubCachedPackageDir works out where pub keeps a hosted package when no
// package_config.json says so: <cache>/hosted/<host>/<name>-<version>.
func pubCachedPackageDir(entry pubLockEntry, name string) string {
	cache := pubCacheDir()
	if cache == "" {
		return ""
	}
	host := "pub.dev"
	if desc, ok := entry.Description.(map[string]any); ok {
		if raw, ok := desc["url"].(string); ok {
			if u, err := url.Parse(raw); err == nil && u.Host != "" && !strings.ContainsAny(u.Host, `/\`) {
				host = u.Host
			}
		}
	}
	if !safePathSegment(entry.Version) {
		return ""
	}
	return filepath.Join(cache, "hosted", host, name+"-"+entry.Version)
}

// pubCacheDir is where pub keeps downloaded packages: PUB_CACHE when set,
// otherwise the platform default pub itself uses.
func pubCacheDir() string {
	if dir := os.Getenv("PUB_CACHE"); dir != "" {
		return dir
	}
	if runtime.GOOS == "windows" {
		if local := os.Getenv("LOCALAPPDATA"); local != "" {
			return filepath.Join(local, "Pub", "Cache")
		}
		return ""
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".pub-cache")
}

// pubPathDescription reads the directory out of a path package's description,
// which pubspec.lock records relative to the project when it was written that
// way in the pubspec.
func pubPathDescription(description any, projectDir string) string {
	desc, ok := description.(map[string]any)
	if !ok {
		return ""
	}
	dir, ok := desc["path"].(string)
	if !ok || dir == "" {
		return ""
	}
	if relative, _ := desc["relative"].(bool); relative || !filepath.IsAbs(dir) {
		return filepath.Join(projectDir, filepath.FromSlash(dir))
	}
	return dir
}
