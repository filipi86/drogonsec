package analyzer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/filipi86/drogonsec/internal/engine"
	"github.com/filipi86/drogonsec/internal/sca"
)

// FingerprintVersion names the scheme, and is part of every fingerprint.
//
// It exists so the scheme can be changed without the change being silent. A
// consumer holding fingerprints from an older scan compares strings; if the
// inputs were altered and the prefix were not, every finding would look new at
// once, and the tool would have no way to say which run the break came from.
// Bump this whenever the inputs below change.
const FingerprintVersion = "v1"

// Fingerprints assigns every finding an identity that survives to the next
// scan.
//
// Nothing else in the output can do this. The SAST Finding.ID was
// rule-basename-line, so inserting an import moved every finding below it, and
// two files of the same name in different directories collided. SCA findings
// had no identifier at all. Without a stable identity an editor cannot show
// "new since last run", a suppression cannot name one occurrence rather than
// every match of a rule in a file, and GitHub code scanning cannot tell a
// reopened alert from a fresh one.
//
// The rule followed throughout is that a fingerprint is built from **what the
// finding is, never from where it sits**. A line number is the first thing an
// unrelated edit changes, so it is not an input; the matched content is, since
// changing it means the finding itself changed. The path is an input, because
// the same flaw in two files is two findings to fix.
//
// Where a file genuinely holds two indistinguishable findings — the same rule
// matching the same text twice — the inputs are equal by construction, so an
// occurrence number is appended. It is assigned in the order the findings are
// held, which sorting has already made deterministic.
func Fingerprints(result *ScanResult) {
	occurrences := make(map[string]int)

	// stamp returns the fingerprint for one set of inputs, disambiguating a
	// repeat of inputs already seen.
	stamp := func(kind string, parts ...string) string {
		sum := sha256.Sum256([]byte(strings.Join(append([]string{FingerprintVersion, kind}, parts...), "\x00")))
		digest := hex.EncodeToString(sum[:])[:16]

		occurrences[digest]++
		if n := occurrences[digest]; n > 1 {
			return fmt.Sprintf("%s-%d", digest, n)
		}
		return digest
	}

	for i := range result.SASTFindings {
		f := &result.SASTFindings[i]
		f.Fingerprint = stamp("sast",
			f.RuleID,
			fingerprintPath(result.TargetPath, f.File),
			// The matched source, with indentation and trailing space removed:
			// reformatting a file should not orphan every finding in it.
			normalizeWhitespace(f.Code),
		)
	}

	for i := range result.LeakFindings {
		f := &result.LeakFindings[i]
		f.Fingerprint = stamp("leak",
			f.RuleID,
			fingerprintPath(result.TargetPath, f.File),
			// The match is already redacted by the time it reaches here, and
			// redaction is deterministic, so it identifies the secret without
			// the fingerprint becoming somewhere the secret is written down.
			f.Match,
			// A secret found in history is a different problem from the same
			// secret still in the working tree, and is fixed differently.
			f.CommitHash,
		)
	}

	for i := range result.SCAFindings {
		f := &result.SCAFindings[i]
		// No path and no line: an SCA finding is a package at a version with an
		// advisory against it, and the manifest says which project's problem it
		// is. The advisory is keyed by CVE where there is one, so the same flaw
		// reported under a different GHSA does not read as new.
		identity := f.CVE
		if identity == "" {
			identity = f.Advisory
		}
		f.Fingerprint = stamp("sca",
			f.Ecosystem,
			f.PackageName,
			f.PackageVersion,
			fingerprintPath(result.TargetPath, f.ManifestFile),
			identity,
		)
	}
}

// fingerprintPath reduces a file path to something that means the same on
// another machine. An absolute path carries the checkout directory, so the same
// repository scanned in /home/alice and in /github/workspace would produce two
// sets of fingerprints for one set of findings.
func fingerprintPath(targetPath, file string) string {
	if rel, err := filepath.Rel(targetPath, file); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(file)
}

// normalizeWhitespace collapses every run of whitespace to a single space and
// trims the ends, so that re-indenting a block or converting tabs to spaces
// leaves its findings identified as they were.
func normalizeWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// fromEngineFinding and fromSCAFinding copy an engine's finding into the
// analyzer's own.
//
// These were struct conversions — Finding(f) — which Go allows only while the
// two declarations stay field-for-field identical, and which therefore broke
// the moment the analyzer needed a field of its own. That is the right way
// round: a fingerprint is computed over a whole scan, after suppression and
// sorting, and neither engine is in a position to produce one. Copying by name
// costs a few lines and stops the engines' types from being pinned to the
// analyzer's.
func fromEngineFinding(f engine.Finding) Finding {
	return Finding{
		ID:            f.ID,
		Type:          f.Type,
		Language:      f.Language,
		Severity:      f.Severity,
		Title:         f.Title,
		Description:   f.Description,
		File:          f.File,
		Line:          f.Line,
		Column:        f.Column,
		Code:          f.Code,
		RuleID:        f.RuleID,
		OWASP:         f.OWASP,
		CWE:           f.CWE,
		CVSS:          f.CVSS,
		References:    f.References,
		Remediation:   f.Remediation,
		AIRemediation: f.AIRemediation,
		FalsePositive: f.FalsePositive,
	}
}

func fromSCAFinding(f sca.Finding) SCAFinding {
	return SCAFinding{
		PackageName:    f.PackageName,
		PackageVersion: f.PackageVersion,
		FixedVersion:   f.FixedVersion,
		Ecosystem:      f.Ecosystem,
		ManifestFile:   f.ManifestFile,
		Severity:       f.Severity,
		CVE:            f.CVE,
		CVSS:           f.CVSS,
		Description:    f.Description,
		Advisory:       f.Advisory,
		OWASP:          f.OWASP,
		Direct:         f.Direct,
		DependencyPath: f.DependencyPath,
	}
}
