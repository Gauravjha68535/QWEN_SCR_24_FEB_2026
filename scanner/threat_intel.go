package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"QWEN_SCR_24_FEB_2026/reporter"
	"QWEN_SCR_24_FEB_2026/utils"
)

// ThreatIntelScanner performs threat intelligence integration
type ThreatIntelScanner struct {
	cveCache    map[string]CVEInfo
	lastUpdate  time.Time
	cacheFile   string
	mitreATTACK map[string]MITRETechnique
}

// CVEInfo represents CVE information
type CVEInfo struct {
	ID          string    `json:"id"`
	Summary     string    `json:"summary"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	CVSSScore   float64   `json:"cvss_score"`
	Published   time.Time `json:"published"`
	Modified    time.Time `json:"modified"`
	References  []string  `json:"references"`
}

// MITRETechnique represents MITRE ATT&CK technique
type MITRETechnique struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tactics     []string `json:"tactics"`
	Platforms   []string `json:"platforms"`
}

// NewThreatIntelScanner creates a new threat intelligence scanner
func NewThreatIntelScanner() *ThreatIntelScanner {
	return &ThreatIntelScanner{
		cveCache:    make(map[string]CVEInfo),
		lastUpdate:  time.Time{},
		cacheFile:   ".threat-intel-cache.json",
		mitreATTACK: loadMITREATTACK(),
	}
}

// ScanWithThreatIntel enhances findings with threat intelligence
func (tis *ThreatIntelScanner) ScanWithThreatIntel(findings []reporter.Finding) ([]reporter.Finding, error) {
	var enhancedFindings []reporter.Finding

	utils.LogInfo("Enhancing findings with threat intelligence...")

	// Load CVE cache
	tis.loadCVECache()

	// Check for CVE updates
	if time.Since(tis.lastUpdate) > 24*time.Hour {
		utils.LogInfo("Updating CVE database...")
		tis.updateCVECache()
	}

	for _, finding := range findings {
		enhancedFinding := finding

		// Enrich with CVE data if applicable
		if strings.Contains(strings.ToUpper(finding.RuleID), "CVE") {
			cveInfo := tis.getCVEInfo(finding.RuleID)
			if cveInfo.ID != "" {
				enhancedFinding.Description = fmt.Sprintf("%s\n\nCVE Details: %s (CVSS: %.1f)",
					finding.Description, cveInfo.Summary, cveInfo.CVSSScore)
				enhancedFinding.Remediation = fmt.Sprintf("%s\n\nReferences: %s",
					finding.Remediation, strings.Join(cveInfo.References, ", "))
			}
		}

		// Map to MITRE ATT&CK
		mitreTechnique := tis.mapToMITRE(finding)
		if mitreTechnique.ID != "" {
			enhancedFinding.Description = fmt.Sprintf("%s\n\nMITRE ATT&CK: %s - %s",
				enhancedFinding.Description, mitreTechnique.ID, mitreTechnique.Name)
		}

		enhancedFindings = append(enhancedFindings, enhancedFinding)
	}

	return enhancedFindings, nil
}

// GenerateThreatIntelReport generates a threat intelligence report
func (tis *ThreatIntelScanner) GenerateThreatIntelReport(findings []reporter.Finding) map[string]interface{} {
	report := map[string]interface{}{
		"generated_at":        time.Now().Format(time.RFC3339),
		"total_findings":      len(findings),
		"cve_findings":        0,
		"exploitable":         0,
		"mitre_techniques":    make(map[string]int),
		"high_priority":       []string{},
		"recent_related_cves": []CVEInfo{},
	}

	cveCount := 0
	mitreMap := make(map[string]int)

	for _, finding := range findings {
		// Count CVE findings
		if strings.Contains(strings.ToUpper(finding.RuleID), "CVE") {
			cveCount++
		}

		// Map to MITRE
		technique := tis.mapToMITRE(finding)
		if technique.ID != "" {
			mitreMap[technique.ID]++
		}

		// Identify high priority (critical + known exploits)
		if finding.Severity == "critical" {
			highPriority := report["high_priority"].([]string)
			highPriority = append(highPriority, fmt.Sprintf("%s: %s", finding.RuleID, finding.IssueName))
			report["high_priority"] = highPriority
		}
	}

	report["cve_findings"] = cveCount
	report["mitre_techniques"] = mitreMap

	return report
}

// Helper functions
func (tis *ThreatIntelScanner) loadCVECache() {
	// Load from cache file
	data, err := os.ReadFile(tis.cacheFile)
	if err != nil {
		return
	}

	if err := json.Unmarshal(data, &tis.cveCache); err != nil {
		utils.LogWarn(fmt.Sprintf("Failed to parse CVE cache: %v", err))
	}
}

func (tis *ThreatIntelScanner) updateCVECache() {
	// Fetch recent CVEs from NVD API
	// https://nvd.nist.gov/vuln/data-feeds

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("GET", "https://services.nvd.nist.gov/rest/json/cves/2.0", nil)
	if err != nil {
		utils.LogWarn(fmt.Sprintf("Failed to create request for CVE cache: %v", err))
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		utils.LogWarn(fmt.Sprintf("Failed to update CVE cache: %v", err))
		return
	}
	defer resp.Body.Close()

	// Parse and update cache
	// Implementation depends on NVD API response format
	// TODO: Add proper JSON unmarshaling for NVD 2.0 API

	tis.lastUpdate = time.Now()
}

func (tis *ThreatIntelScanner) getCVEInfo(cveID string) CVEInfo {
	if info, exists := tis.cveCache[cveID]; exists {
		return info
	}

	// Fetch from NVD API if not in cache
	// Implementation omitted for brevity

	return CVEInfo{}
}

func (tis *ThreatIntelScanner) mapToMITRE(finding reporter.Finding) MITRETechnique {
	// Map finding to MITRE ATT&CK technique
	findingType := strings.ToLower(finding.IssueName)

	for _, technique := range tis.mitreATTACK {
		if strings.Contains(findingType, strings.ToLower(technique.Name)) {
			return technique
		}
	}

	// Default mappings
	if strings.Contains(findingType, "sql injection") {
		return tis.mitreATTACK["T1190"] // Exploit Public-Facing Application
	}
	if strings.Contains(findingType, "command injection") {
		return tis.mitreATTACK["T1059"] // Command and Scripting Interpreter
	}
	if strings.Contains(findingType, "xss") {
		return tis.mitreATTACK["T1189"] // Drive-by Compromise
	}

	return MITRETechnique{}
}

func loadMITREATTACK() map[string]MITRETechnique {
	return map[string]MITRETechnique{
		"T1190": {
			ID:          "T1190",
			Name:        "Exploit Public-Facing Application",
			Description: "Adversaries may attempt to exploit a weakness in an Internet-facing host or system",
			Tactics:     []string{"Initial Access"},
			Platforms:   []string{"Containers", "IaaS", "Linux", "Windows", "macOS"},
		},
		"T1059": {
			ID:          "T1059",
			Name:        "Command and Scripting Interpreter",
			Description: "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries",
			Tactics:     []string{"Execution"},
			Platforms:   []string{"Linux", "Windows", "macOS"},
		},
		"T1189": {
			ID:          "T1189",
			Name:        "Drive-by Compromise",
			Description: "Adversaries may gain access to a system through a user visiting a website over the normal course of browsing",
			Tactics:     []string{"Initial Access"},
			Platforms:   []string{"Linux", "Windows", "macOS"},
		},
		"T1078": {
			ID:          "T1078",
			Name:        "Valid Accounts",
			Description: "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access",
			Tactics:     []string{"Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"},
			Platforms:   []string{"Containers", "IaaS", "Linux", "Windows", "macOS"},
		},
		"T1040": {
			ID:          "T1040",
			Name:        "Network Sniffing",
			Description: "Adversaries may sniff network traffic to capture information about an environment",
			Tactics:     []string{"Credential Access", "Discovery"},
			Platforms:   []string{"Linux", "Windows", "macOS"},
		},
	}
}
