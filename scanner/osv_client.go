package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"QWEN_SCR_24_FEB_2026/reporter"
	"QWEN_SCR_24_FEB_2026/utils"
)

// OSVBatchQuery represents a batch query to the OSV API
type OSVBatchQuery struct {
	Queries []OSVSingleQuery `json:"queries"`
}

// OSVSingleQuery represents a single query in a batch
type OSVSingleQuery struct {
	Package OSVPackageRef `json:"package"`
	Version string        `json:"version,omitempty"`
}

// OSVPackageRef represents a package reference for OSV queries
type OSVPackageRef struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// OSVBatchResponse represents the batch response from the OSV API
type OSVBatchResponse struct {
	Results []OSVBatchResult `json:"results"`
}

// OSVBatchResult represents a single result in a batch response
type OSVBatchResult struct {
	Vulns []OSVVulnerability `json:"vulns"`
}

// ScanDependenciesWithOSV performs enhanced SCA by querying the OSV.dev batch API
func ScanDependenciesWithOSV(targetDir string) ([]reporter.Finding, error) {
	utils.LogInfo("🔍 Starting Software Composition Analysis (OSV.dev Batch API)...")

	// Reuse the existing dependency collection
	deps := collectDependencies(targetDir)
	if len(deps) == 0 {
		utils.LogInfo("No dependencies found for SCA analysis")
		return nil, nil
	}

	utils.LogInfo(fmt.Sprintf("Found %d dependencies to check against OSV database", len(deps)))

	// Build batch queries
	queries := make([]OSVSingleQuery, 0, len(deps))
	var queryIndices []int

	for idx, dep := range deps {
		ecosystem := dep.Ecosystem
		if ecosystem == "" {
			continue
		}
		queries = append(queries, OSVSingleQuery{
			Package: OSVPackageRef{
				Name:      dep.Name,
				Ecosystem: ecosystem,
			},
			Version: dep.Version,
		})
		queryIndices = append(queryIndices, idx)
	}

	if len(queries) == 0 {
		return nil, nil
	}

	var allFindings []reporter.Finding
	srNo := 1
	client := &http.Client{Timeout: 30 * time.Second}

	// Process in batches of 100 (OSV API limit)
	batchSize := 100
	for i := 0; i < len(queries); i += batchSize {
		end := i + batchSize
		if end > len(queries) {
			end = len(queries)
		}
		batch := queries[i:end]

		batchQuery := OSVBatchQuery{Queries: batch}
		jsonData, err := json.Marshal(batchQuery)
		if err != nil {
			utils.LogWarn(fmt.Sprintf("Failed to marshal OSV batch query: %v", err))
			continue
		}

		resp, err := client.Post("https://api.osv.dev/v1/querybatch", "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			utils.LogWarn(fmt.Sprintf("OSV batch API request failed: %v", err))
			continue
		}

		if resp.StatusCode != 200 {
			resp.Body.Close()
			utils.LogWarn(fmt.Sprintf("OSV batch API returned status %d", resp.StatusCode))
			continue
		}

		var batchResp OSVBatchResponse
		if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
			resp.Body.Close()
			utils.LogWarn(fmt.Sprintf("Failed to decode OSV batch response: %v", err))
			continue
		}
		resp.Body.Close()

		for j, result := range batchResp.Results {
			queryIdx := i + j
			if queryIdx >= len(queryIndices) {
				break
			}
			originalIdx := queryIndices[queryIdx]
			dep := deps[originalIdx]

			for _, vuln := range result.Vulns {
				severity := mapOSVSeverity(vuln.Severity)
				fixedVersion := getFixedVersion(vuln, dep.Ecosystem)

				summary := vuln.Summary
				if summary == "" {
					summary = vuln.Details
				}
				if len(summary) > 200 {
					summary = summary[:200] + "..."
				}

				description := fmt.Sprintf("Known vulnerability %s in %s@%s: %s",
					vuln.ID, dep.Name, dep.Version, summary)

				allFindings = append(allFindings, reporter.Finding{
					SrNo:        srNo,
					IssueName:   fmt.Sprintf("SCA: %s in %s", vuln.ID, dep.Name),
					FilePath:    dep.SourceFile,
					Description: description,
					Severity:    severity,
					LineNumber:  fmt.Sprintf("%d", dep.LineNumber),
					AiValidated: "N/A (CVE Database)",
					Remediation: fmt.Sprintf("Upgrade %s to version %s or later", dep.Name, fixedVersion),
					RuleID:      fmt.Sprintf("sca-%s", strings.ToLower(vuln.ID)),
					Source:      "osv-sca",
					CWE:         "CWE-1035",
					OWASP:       "A06:2021",
					Confidence:  1.0,
				})
				srNo++
			}
		}
	}

	utils.LogInfo(fmt.Sprintf("SCA complete: found %d known vulnerabilities", len(allFindings)))
	return allFindings, nil
}
