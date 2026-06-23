package reporter

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/filipi86/drogonsec/internal/analyzer"
)

// ============= CYCLONEDX SBOM REPORTER =============
// Emits a CycloneDX 1.5 JSON Software Bill of Materials of the dependencies
// discovered by the SCA engine. This is a flat component inventory (one
// component per discovered dependency); it does not yet express the transitive
// dependency graph, because the SCA engine resolves manifests rather than full
// lockfiles. The output is consumable by Grype, Trivy, and Dependency-Track.

// purlTypes maps the SCA engine's ecosystem names to Package URL (purl) types.
// See https://github.com/package-url/purl-spec for the canonical type list.
var purlTypes = map[string]string{
	"npm":       "npm",
	"pypi":      "pypi",
	"go":        "golang",
	"maven":     "maven",
	"rubygems":  "gem",
	"packagist": "composer",
	"pub":       "pub",
}

// purlFor builds a Package URL for a dependency. Name segments separated by "/"
// (a golang module path, an npm scope) are treated as namespace separators and
// preserved; each segment is percent-encoded. "@" is encoded to %40 so it is
// never confused with the version separator.
func purlFor(ecosystem, name, version string) string {
	t := purlTypes[strings.ToLower(ecosystem)]
	if t == "" {
		t = strings.ToLower(ecosystem)
	}
	p := "pkg:" + t + "/" + encodePurlPath(name)
	if version != "" {
		p += "@" + encodePurlSegment(version)
	}
	return p
}

func encodePurlPath(s string) string {
	parts := strings.Split(s, "/")
	for i, p := range parts {
		parts[i] = encodePurlSegment(p)
	}
	return strings.Join(parts, "/")
}

func encodePurlSegment(s string) string {
	// url.PathEscape leaves "@" unescaped (it is a legal path char), but in a
	// purl "@" introduces the version, so it must be percent-encoded.
	return strings.ReplaceAll(url.PathEscape(s), "@", "%40")
}

type cdxBOM struct {
	BOMFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion"`
	SerialNumber string         `json:"serialNumber,omitempty"`
	Version      int            `json:"version"`
	Metadata     cdxMetadata    `json:"metadata"`
	Components   []cdxComponent `json:"components"`
}

type cdxMetadata struct {
	Timestamp string        `json:"timestamp"`
	Tools     cdxTools      `json:"tools"`
	Component *cdxComponent `json:"component,omitempty"`
}

type cdxTools struct {
	Components []cdxComponent `json:"components"`
}

type cdxComponent struct {
	Type    string `json:"type"`
	BOMRef  string `json:"bom-ref,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
}

// CycloneDXReporter writes a CycloneDX 1.5 SBOM.
type CycloneDXReporter struct{}

func (r *CycloneDXReporter) Write(result *analyzer.ScanResult, w io.Writer) error {
	bom := buildCycloneDX(result)
	sn, err := newSerialNumber()
	if err == nil {
		bom.SerialNumber = sn
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(bom)
}

// buildCycloneDX assembles the BOM from a scan result. It is deterministic
// (the serial number is added by the caller) so it can be unit-tested directly.
func buildCycloneDX(result *analyzer.ScanResult) cdxBOM {
	ts := result.ScanTime
	if ts.IsZero() {
		ts = time.Now()
	}

	// Dedup by purl: the same dependency can appear in several manifests, or in
	// both the prod and dev dependency maps of one manifest.
	seen := make(map[string]bool)
	var components []cdxComponent
	for _, d := range result.Dependencies {
		purl := purlFor(d.Ecosystem, d.Name, d.Version)
		if seen[purl] {
			continue
		}
		seen[purl] = true
		components = append(components, cdxComponent{
			Type:    "library",
			BOMRef:  purl,
			Name:    d.Name,
			Version: d.Version,
			PURL:    purl,
		})
	}
	// Stable ordering for reproducible output.
	sort.Slice(components, func(i, j int) bool {
		return components[i].BOMRef < components[j].BOMRef
	})

	name := filepath.Base(result.TargetPath)
	if name == "." || name == "" || name == string(filepath.Separator) {
		name = "application"
	}

	return cdxBOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Metadata: cdxMetadata{
			Timestamp: ts.UTC().Format(time.RFC3339),
			Tools: cdxTools{
				Components: []cdxComponent{{
					Type:    "application",
					Name:    "DrogonSec Security Scanner",
					Version: result.Version,
				}},
			},
			Component: &cdxComponent{
				Type:   "application",
				BOMRef: "root:" + name,
				Name:   name,
			},
		},
		Components: components,
	}
}

// newSerialNumber returns a CycloneDX urn:uuid serial number (UUID v4).
func newSerialNumber() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
