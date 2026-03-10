package scanner

import (
	"fmt"
	"os"
	"strings"
	"time"

	"QWEN_SCR_24_FEB_2026/reporter"
	"QWEN_SCR_24_FEB_2026/utils"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// SupplyChainScanner performs supply chain security analysis
type SupplyChainScanner struct {
	dependencies []Dependency
	sbom         *cdx.BOM
}

// NewSupplyChainScanner creates a new supply chain scanner
func NewSupplyChainScanner() *SupplyChainScanner {
	return &SupplyChainScanner{
		dependencies: make([]Dependency, 0),
		sbom: &cdx.BOM{
			SpecVersion: cdx.SpecVersion1_4,
			Version:     1,
			Metadata: &cdx.Metadata{
				Timestamp: time.Now().Format(time.RFC3339),
				Tools: &cdx.ToolsChoice{
					Tools: &[]cdx.Tool{
						{
							Name:    "AI Security Scanner",
							Version: "2.0.0",
						},
					},
				},
			},
			Components: &[]cdx.Component{},
		},
	}
}

// ScanSupplyChain performs comprehensive supply chain security analysis
func (scs *SupplyChainScanner) ScanSupplyChain(targetDir string) ([]reporter.Finding, error) {
	var findings []reporter.Finding

	utils.LogInfo("Starting supply chain security analysis...")

	// Collect all dependencies
	scs.dependencies = scs.collectAllDependencies(targetDir)
	utils.LogInfo(fmt.Sprintf("Found %d dependencies", len(scs.dependencies)))

	// Generate SBOM
	scs.generateSBOM()

	// Check for vulnerabilities
	vulnFindings := scs.checkDependencyVulnerabilities()
	findings = append(findings, vulnFindings...)

	// Check for typosquatting
	typoFindings := scs.checkTyposquatting()
	findings = append(findings, typoFindings...)

	// Check license compliance
	licenseFindings := scs.checkLicenseCompliance()
	findings = append(findings, licenseFindings...)

	// Check for outdated dependencies
	outdatedFindings := scs.checkOutdatedDependencies()
	findings = append(findings, outdatedFindings...)

	return findings, nil
}

// GenerateSBOMFile exports SBOM to file
func (scs *SupplyChainScanner) GenerateSBOMFile(outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := cdx.NewBOMEncoder(file, cdx.BOMFileFormatJSON)
	encoder.SetPretty(true)
	return encoder.Encode(scs.sbom)
}

func (scs *SupplyChainScanner) collectAllDependencies(targetDir string) []Dependency {
	// Note: Manual dependency parsing is currently disabled in favor of using OSV-Scanner natively.
	// OSV-Scanner directly reads package files and returns vulnerabilities.
	return []Dependency{}
}

func (scs *SupplyChainScanner) generateSBOM() {
	for _, dep := range scs.dependencies {
		component := cdx.Component{
			BOMRef:     fmt.Sprintf("%s@%s", dep.Name, dep.Version),
			Type:       cdx.ComponentTypeLibrary,
			Name:       dep.Name,
			Version:    dep.Version,
			PackageURL: dep.Purl,
			Scope:      cdx.ScopeRequired,
		}

		// Add hashes
		if dep.Hash != "" {
			component.Hashes = &[]cdx.Hash{
				{
					Algorithm: cdx.HashAlgoSHA256,
					Value:     dep.Hash,
				},
			}
		}

		*scs.sbom.Components = append(*scs.sbom.Components, component)
	}
}

func (scs *SupplyChainScanner) checkDependencyVulnerabilities() []reporter.Finding {
	var findings []reporter.Finding
	srNo := 1

	// Check against OSV database
	for _, dep := range scs.dependencies {
		vulns, err := queryOSV(dep)
		if err != nil {
			continue
		}

		for _, vuln := range vulns {
			findings = append(findings, reporter.Finding{
				SrNo:        srNo,
				IssueName:   fmt.Sprintf("CVE: %s - %s", vuln.ID, dep.Name),
				FilePath:    dep.SourceFile,
				Description: fmt.Sprintf("Vulnerable dependency: %s@%s - %s", dep.Name, dep.Version, vuln.Summary),
				Severity:    mapOSVSeverity(vuln.Severity),
				LineNumber:  "1",
				AiValidated: "No",
				Remediation: fmt.Sprintf("Update %s to version %s or later", dep.Name, getFixedVersion(vuln, dep.Ecosystem)),
				RuleID:      vuln.ID,
				Source:      "supply-chain",
			})
			srNo++
		}
	}

	return findings
}

func (scs *SupplyChainScanner) checkTyposquatting() []reporter.Finding {
	var findings []reporter.Finding
	srNo := 1

	// Known typosquatting patterns
	typosquatPatterns := map[string][]string{
		"requests": {"reqeusts", "requets", "requestss"},
		"numpy":    {"numpi", "nunpy", "nmpy"},
		"pandas":   {"panda", "pandass", "pandad"},
		"lodash":   {"l0dash", "1odash", "lodahs"},
		"express":  {"expess", "expresss", "exress"},
		"react":    {"reacct", "rect", "raect"},
		"axios":    {"axois", "aixos", "axiox"},
		"moment":   {"momnet", "mome nt", "mmoment"},
		"webpack":  {"webpakc", "webpak", "weback"},
		"babel":    {"bab el", "bael", "babeljs"},
	}

	for _, dep := range scs.dependencies {
		for legitimate, typos := range typosquatPatterns {
			for _, typo := range typos {
				if strings.EqualFold(dep.Name, typo) {
					findings = append(findings, reporter.Finding{
						SrNo:        srNo,
						IssueName:   "Typosquatting Detected",
						FilePath:    dep.SourceFile,
						Description: fmt.Sprintf("Potential typosquatting package: %s (did you mean %s?)", dep.Name, legitimate),
						Severity:    "critical",
						LineNumber:  "1",
						AiValidated: "No",
						Remediation: fmt.Sprintf("Replace %s with %s in your dependencies", dep.Name, legitimate),
						RuleID:      "typosquatting-" + legitimate,
						Source:      "supply-chain",
					})
					srNo++
				}
			}
		}
	}

	return findings
}

func (scs *SupplyChainScanner) checkLicenseCompliance() []reporter.Finding {
	var findings []reporter.Finding
	srNo := 1

	// Restrictive licenses that may require attention
	restrictiveLicenses := []string{
		"GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0",
		"CC-BY-NC", "CC-BY-NC-SA", "SSPL", "Elastic-2.0",
	}

	for _, dep := range scs.dependencies {
		if dep.License != "" {
			for _, restrictive := range restrictiveLicenses {
				if strings.Contains(strings.ToUpper(dep.License), strings.ToUpper(restrictive)) {
					findings = append(findings, reporter.Finding{
						SrNo:        srNo,
						IssueName:   "Restrictive License Detected",
						FilePath:    dep.SourceFile,
						Description: fmt.Sprintf("Dependency %s uses %s license which may have compliance implications", dep.Name, dep.License),
						Severity:    "medium",
						LineNumber:  "1",
						AiValidated: "No",
						Remediation: fmt.Sprintf("Review %s license terms and ensure compliance with your organization's policies", dep.Name),
						RuleID:      "license-" + restrictive,
						Source:      "supply-chain",
					})
					srNo++
				}
			}
		}
	}

	return findings
}

func (scs *SupplyChainScanner) checkOutdatedDependencies() []reporter.Finding {
	var findings []reporter.Finding
	srNo := 1

	// Check if dependencies are significantly outdated
	// This would typically query npm/pypi APIs for latest versions
	// For now, we'll flag dependencies with very old versions

	for _, dep := range scs.dependencies {
		if isVersionOutdated(dep.Version) {
			findings = append(findings, reporter.Finding{
				SrNo:        srNo,
				IssueName:   "Outdated Dependency",
				FilePath:    dep.SourceFile,
				Description: fmt.Sprintf("Dependency %s@%s may be significantly outdated", dep.Name, dep.Version),
				Severity:    "low",
				LineNumber:  "1",
				AiValidated: "No",
				Remediation: fmt.Sprintf("Consider updating %s to the latest version", dep.Name),
				RuleID:      "outdated-" + dep.Name,
				Source:      "supply-chain",
			})
			srNo++
		}
	}

	return findings
}

// Helper functions

func isVersionOutdated(version string) bool {
	// Simple heuristic: versions starting with 0. or 1. may be outdated
	return strings.HasPrefix(version, "0.") || strings.HasPrefix(version, "1.0")
}
