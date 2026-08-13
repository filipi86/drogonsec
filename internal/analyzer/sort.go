package analyzer

import "sort"

// SortFindings orders every finding list by descending severity, so a scan
// leads with CRITICAL, then HIGH, MEDIUM, LOW and INFO.
//
// It is applied once, to the scan result, rather than in each reporter: the
// text, JSON, SARIF, HTML and CycloneDX writers all read these slices, and
// ordering them here is what keeps every output — and any consumer of the JSON
// or SARIF — in the same order.
//
// Within a severity the order is fully determined, so two scans of unchanged
// code produce byte-identical reports and a diff between two scans shows real
// changes rather than reordering. The tie-breakers put the highest CVSS first
// and then fall back to location.
func SortFindings(result *ScanResult) {
	if result == nil {
		return
	}

	sort.SliceStable(result.SASTFindings, func(i, j int) bool {
		a, b := result.SASTFindings[i], result.SASTFindings[j]
		if wa, wb := a.Severity.Weight(), b.Severity.Weight(); wa != wb {
			return wa > wb
		}
		if a.CVSS != b.CVSS {
			return a.CVSS > b.CVSS
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.RuleID < b.RuleID
	})

	sort.SliceStable(result.LeakFindings, func(i, j int) bool {
		a, b := result.LeakFindings[i], result.LeakFindings[j]
		if wa, wb := a.Severity.Weight(), b.Severity.Weight(); wa != wb {
			return wa > wb
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.RuleID < b.RuleID
	})

	sort.SliceStable(result.SCAFindings, func(i, j int) bool {
		a, b := result.SCAFindings[i], result.SCAFindings[j]
		if wa, wb := a.Severity.Weight(), b.Severity.Weight(); wa != wb {
			return wa > wb
		}
		if a.CVSS != b.CVSS {
			return a.CVSS > b.CVSS
		}
		if a.PackageName != b.PackageName {
			return a.PackageName < b.PackageName
		}
		return a.CVE < b.CVE
	})
}
