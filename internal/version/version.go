// Package version carries the build identity of the binary: the release
// version, the commit it was built from, and when. It is the single source of
// truth for those values — the CLI banner, the version command and the scan
// report metadata all read them from here.
//
// The values are injected at link time via ldflags:
//
//	go build -ldflags "-X github.com/filipi86/drogonsec/internal/version.Version=0.2.0"
//
// When they are not injected — a plain `go build`, or `go install ...@latest`,
// which the README documents as an install path — they are recovered from the
// module build information embedded by the Go toolchain, so an un-flagged build
// still reports what it actually is instead of a literal that goes stale.
package version

import (
	"runtime"
	"runtime/debug"
	"strings"
)

// Injected at link time. Empty values are resolved from the embedded build
// information by the package initializer below.
var (
	// Version is the semantic version, without a leading "v".
	Version string
	// BuildTime is the build timestamp in RFC 3339 (UTC).
	BuildTime string
	// GitCommit is the short hash of the commit the binary was built from.
	GitCommit string
)

const unknown = "unknown"

func init() {
	resolve(debug.ReadBuildInfo)
}

// resolve fills in whatever ldflags did not provide. It takes the build-info
// reader as a parameter so tests can drive it without relying on how the test
// binary itself happens to have been built.
func resolve(readBuildInfo func() (*debug.BuildInfo, bool)) {
	info, ok := readBuildInfo()
	ok = ok && info != nil

	if Version == "" {
		// Main.Version is the module version when installed with
		// `go install module@version`, and "(devel)" for a local build.
		if ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			Version = strings.TrimPrefix(info.Main.Version, "v")
		} else {
			Version = "dev"
		}
	}

	if ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if GitCommit == "" {
					GitCommit = shortHash(s.Value)
				}
			case "vcs.time":
				if BuildTime == "" {
					BuildTime = s.Value
				}
			}
		}
	}

	if GitCommit == "" {
		GitCommit = unknown
	}
	if BuildTime == "" {
		BuildTime = unknown
	}
}

// shortHash truncates a full commit hash to the 7 characters Git shows by
// default. Values already shorter than that are returned untouched.
func shortHash(hash string) string {
	const short = 7
	if len(hash) > short {
		return hash[:short]
	}
	return hash
}

// String renders the version the way it is shown to users, e.g. "v0.2.0".
func String() string {
	return "v" + Version
}

// Short reduces the version to its release core, dropping any git-describe
// suffix: "0.2.0-3-gabc1234" becomes "v0.2.0". The CLI banner draws a
// fixed-width box, so it needs a version string whose length cannot grow with
// the distance from the last tag.
func Short() string {
	core, _, _ := strings.Cut(Version, "-")
	return "v" + core
}

// GoVersion reports the Go toolchain that produced the binary. It is read from
// the runtime rather than injected, so it can never disagree with reality.
func GoVersion() string {
	return strings.TrimPrefix(runtime.Version(), "go")
}
