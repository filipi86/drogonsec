package version

import (
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

// withVars runs fn with the package-level build variables set to the given
// values and restores them afterwards, so tests do not leak state into each
// other or depend on how the test binary itself was built.
func withVars(t *testing.T, ver, buildTime, commit string, fn func()) {
	t.Helper()
	origVer, origTime, origCommit := Version, BuildTime, GitCommit
	t.Cleanup(func() {
		Version, BuildTime, GitCommit = origVer, origTime, origCommit
	})
	Version, BuildTime, GitCommit = ver, buildTime, commit
	fn()
}

// noBuildInfo simulates a binary with no embedded module information.
func noBuildInfo() (*debug.BuildInfo, bool) { return nil, false }

func buildInfoWith(mainVersion string, settings ...debug.BuildSetting) func() (*debug.BuildInfo, bool) {
	return func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Main:     debug.Module{Version: mainVersion},
			Settings: settings,
		}, true
	}
}

// TestResolveKeepsInjectedValues is the release path: the Makefile passes all
// three via ldflags, and nothing may overwrite them.
func TestResolveKeepsInjectedValues(t *testing.T) {
	withVars(t, "1.2.3", "2026-01-02T03:04:05Z", "abc1234", func() {
		resolve(buildInfoWith("v9.9.9",
			debug.BuildSetting{Key: "vcs.revision", Value: "deadbeefdeadbeef"},
			debug.BuildSetting{Key: "vcs.time", Value: "2020-01-01T00:00:00Z"},
		))

		if Version != "1.2.3" {
			t.Errorf("Version = %q, want the injected %q", Version, "1.2.3")
		}
		if BuildTime != "2026-01-02T03:04:05Z" {
			t.Errorf("BuildTime = %q, want the injected value", BuildTime)
		}
		if GitCommit != "abc1234" {
			t.Errorf("GitCommit = %q, want the injected value", GitCommit)
		}
	})
}

// TestResolveRecoversFromBuildInfo is the `go install ...@latest` path, which
// the README documents as an install method. No ldflags are applied there, so
// the values have to come from the embedded module information.
func TestResolveRecoversFromBuildInfo(t *testing.T) {
	withVars(t, "", "", "", func() {
		resolve(buildInfoWith("v0.2.0",
			debug.BuildSetting{Key: "vcs.revision", Value: "1234567890abcdef"},
			debug.BuildSetting{Key: "vcs.time", Value: "2026-08-13T12:00:00Z"},
		))

		if Version != "0.2.0" {
			t.Errorf("Version = %q, want %q with the leading v stripped", Version, "0.2.0")
		}
		if GitCommit != "1234567" {
			t.Errorf("GitCommit = %q, want the 7-character short hash %q", GitCommit, "1234567")
		}
		if BuildTime != "2026-08-13T12:00:00Z" {
			t.Errorf("BuildTime = %q, want the vcs.time value", BuildTime)
		}
	})
}

// TestResolveLocalBuild covers a plain `go build` of a checkout: the module
// version reads "(devel)", which is not a version anyone should see.
func TestResolveLocalBuild(t *testing.T) {
	withVars(t, "", "", "", func() {
		resolve(buildInfoWith("(devel)"))

		if Version != "dev" {
			t.Errorf("Version = %q, want %q for a local build", Version, "dev")
		}
		if GitCommit != unknown {
			t.Errorf("GitCommit = %q, want %q with no VCS information", GitCommit, unknown)
		}
		if BuildTime != unknown {
			t.Errorf("BuildTime = %q, want %q with no VCS information", BuildTime, unknown)
		}
	})
}

func TestResolveWithoutBuildInfo(t *testing.T) {
	withVars(t, "", "", "", func() {
		resolve(noBuildInfo)

		if Version != "dev" {
			t.Errorf("Version = %q, want %q", Version, "dev")
		}
		if GitCommit != unknown || BuildTime != unknown {
			t.Errorf("GitCommit = %q, BuildTime = %q, want both %q", GitCommit, BuildTime, unknown)
		}
	})
}

// TestResolveFillsOnlyTheGaps covers the CI build, where the Makefile injects a
// version but the surrounding values still come from the build info.
func TestResolveFillsOnlyTheGaps(t *testing.T) {
	withVars(t, "3.0.0", "", "", func() {
		resolve(buildInfoWith("v0.2.0",
			debug.BuildSetting{Key: "vcs.revision", Value: "fedcba9876543210"},
		))

		if Version != "3.0.0" {
			t.Errorf("Version = %q, want the injected %q", Version, "3.0.0")
		}
		if GitCommit != "fedcba9" {
			t.Errorf("GitCommit = %q, want it recovered from build info", GitCommit)
		}
	})
}

func TestString(t *testing.T) {
	withVars(t, "0.2.0", "", "", func() {
		if got := String(); got != "v0.2.0" {
			t.Errorf("String() = %q, want %q", got, "v0.2.0")
		}
	})
}

// TestShortStaysBounded matters because the CLI banner draws a fixed-width
// box: a version that grows with the distance from the last tag would push the
// right-hand border off the line.
func TestShortStaysBounded(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{"0.2.0", "v0.2.0"},
		{"0.2.0-dirty", "v0.2.0"},
		{"0.2.0-3-gabc1234", "v0.2.0"},
		{"dev", "vdev"},
		{"1.10.25-rc1", "v1.10.25"},
	}

	for _, tt := range tests {
		withVars(t, tt.version, "", "", func() {
			got := Short()
			if got != tt.want {
				t.Errorf("Short() with Version %q = %q, want %q", tt.version, got, tt.want)
			}
			// The banner line has roughly a dozen characters of slack; anything
			// near that is a sign the bound was lost.
			if len(got) > 16 {
				t.Errorf("Short() = %q is %d characters, too long for the banner box", got, len(got))
			}
		})
	}
}

func TestGoVersionReportsTheRuntime(t *testing.T) {
	got := GoVersion()
	if got == "" {
		t.Fatal("GoVersion() is empty")
	}
	if strings.HasPrefix(got, "go") {
		t.Errorf("GoVersion() = %q, want the bare number without the go prefix", got)
	}
	if want := strings.TrimPrefix(runtime.Version(), "go"); got != want {
		t.Errorf("GoVersion() = %q, want %q", got, want)
	}
}

func TestShortHash(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"1234567890abcdef", "1234567"},
		{"1234567", "1234567"},
		{"123", "123"},
		{"", ""},
	}

	for _, tt := range tests {
		if got := shortHash(tt.in); got != tt.want {
			t.Errorf("shortHash(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
