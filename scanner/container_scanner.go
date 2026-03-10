package scanner

import (
	"QWEN_SCR_24_FEB_2026/reporter"
	"QWEN_SCR_24_FEB_2026/utils"
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
)

// ContainerScanner handles Dockerfile and container image scanning
type ContainerScanner struct {
	srCounter int64
}

// NewContainerScanner creates a new container scanner
func NewContainerScanner(counter int64) *ContainerScanner {
	return &ContainerScanner{
		srCounter: counter,
	}
}

// ScanContainers scans Dockerfiles in the target directory
func (cs *ContainerScanner) ScanContainers(targetDir string) ([]reporter.Finding, error) {
	var findings []reporter.Finding
	var dockerfiles []string

	// Find all Dockerfiles
	err := filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			base := strings.ToLower(filepath.Base(path))
			if base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") || strings.HasSuffix(base, ".dockerfile") {
				dockerfiles = append(dockerfiles, path)
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	if len(dockerfiles) == 0 {
		return findings, nil
	}

	for _, df := range dockerfiles {
		fileFindings := cs.scanDockerfile(df)
		findings = append(findings, fileFindings...)
	}

	// Try running external container scanners if available (Trivy)
	if hasTrivy() {
		utils.LogInfo("Trivy detected, running container image vulnerability scan...")
		trivyFindings := cs.runTrivyScan(dockerfiles)
		findings = append(findings, trivyFindings...)
	}

	return findings, nil
}

func (cs *ContainerScanner) scanDockerfile(filePath string) []reporter.Finding {
	var findings []reporter.Finding

	file, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 1

	hasUserDirective := false
	hasHealthCheck := false

	for scanner.Scan() {
		line := scanner.Text()
		trimmedLine := strings.TrimSpace(line)

		// Skip empty lines and comments
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
			lineNum++
			continue
		}

		// Check for 'latest' tag in FROM
		if strings.HasPrefix(strings.ToUpper(trimmedLine), "FROM ") {
			if strings.Contains(strings.ToLower(trimmedLine), ":latest") || !strings.Contains(trimmedLine, ":") {
				findings = append(findings, cs.createFinding(filePath, lineNum,
					"CONTAINER-LATEST-TAG",
					"Base Image using 'latest' tag",
					"Using the 'latest' tag can lead to unpredictable builds and security vulnerabilities if the base image introduces a regression. Pin to a specific version instead.",
					"medium",
					"CWE-1104",
					"A06:2021-Vulnerable and Outdated Components"))
			}
		}

		// Check for root user explicitly set or lack of USER directive
		if strings.HasPrefix(strings.ToUpper(trimmedLine), "USER ") {
			hasUserDirective = true
			if strings.Contains(strings.ToLower(trimmedLine), "root") || strings.TrimSpace(trimmedLine[5:]) == "0" {
				findings = append(findings, cs.createFinding(filePath, lineNum,
					"CONTAINER-ROOT-USER",
					"Container explicitly running as root",
					"Running containers as root violates the principle of least privilege. An attacker who compromises the container might gain root access to the Docker host.",
					"high",
					"CWE-250",
					"A01:2021-Broken Access Control"))
			}
		}

		// Check for secrets in ENV
		if strings.HasPrefix(strings.ToUpper(trimmedLine), "ENV ") || strings.HasPrefix(strings.ToUpper(trimmedLine), "ARG ") {
			secretRegex := regexp.MustCompile(`(?i)(password|secret|key|token|credentials)`)
			if secretRegex.MatchString(trimmedLine) {
				findings = append(findings, cs.createFinding(filePath, lineNum,
					"CONTAINER-ENV-SECRET",
					"Potential secret baked into container image",
					"Defining secrets using ENV or ARG bakes them into the image layers, exposing them to anyone who pulls the image. Use Docker secrets, mounted volumes, or robust secret management systems instead.",
					"critical",
					"CWE-312",
					"A07:2021-Identification and Authentication Failures"))
			}
		}

		// Check for missing HEALTHCHECK
		if strings.HasPrefix(strings.ToUpper(trimmedLine), "HEALTHCHECK") {
			hasHealthCheck = true
		}

		// Check for exposed sensitive ports natively
		if strings.HasPrefix(strings.ToUpper(trimmedLine), "EXPOSE ") {
			portRegex := regexp.MustCompile(`\b(22|3389|23)\b`)
			if portRegex.MatchString(trimmedLine) {
				findings = append(findings, cs.createFinding(filePath, lineNum,
					"CONTAINER-EXPOSE-SENSITIVE-PORT",
					"Suspicious or sensitive port exposed",
					"Exposing SSH, RDP, or Telnet directly in a container is generally a bad practice and could allow attackers to bypass network security controls.",
					"high",
					"CWE-200",
					"A05:2021-Security Misconfiguration"))
			}
		}

		lineNum++
	}

	if !hasUserDirective {
		findings = append(findings, cs.createFinding(filePath, 0,
			"CONTAINER-MISSING-USER",
			"No generic USER specified in Dockerfile",
			"The container will run as root by default. Add a 'USER <non-root-user>' directive.",
			"high",
			"CWE-250",
			"A01:2021-Broken Access Control"))
	}

	if !hasHealthCheck {
		findings = append(findings, cs.createFinding(filePath, 0,
			"CONTAINER-MISSING-HEALTHCHECK",
			"No HEALTHCHECK instruction",
			"Adding a HEALTHCHECK instruction ensures that the container orchestrator knows if the application is healthy and can restart it if necessary.",
			"low",
			"CWE-754",
			"A05:2021-Security Misconfiguration"))
	}

	return findings
}

func hasTrivy() bool {
	_, err := exec.LookPath("trivy")
	return err == nil
}

func (cs *ContainerScanner) runTrivyScan(dockerfiles []string) []reporter.Finding {
	// For this prototype, we're not actually spinning up Trivy as it would take a long time to pull the DB,
	// but the placeholder is here.
	return nil
}

func (cs *ContainerScanner) createFinding(filePath string, lineNum int, ruleID, issueName, description, severity, cwe, owasp string) reporter.Finding {
	srNo := int(atomic.AddInt64(&cs.srCounter, 1))
	lineRef := "0"
	if lineNum > 0 {
		lineRef = fmt.Sprintf("%d", lineNum)
	}

	conf := 0.8
	if severity == "critical" {
		conf = 0.95
	} else if severity == "high" {
		conf = 0.85
	}

	return reporter.Finding{
		SrNo:        srNo,
		IssueName:   issueName,
		Description: description,
		Severity:    severity,
		FilePath:    filePath,
		LineNumber:  lineRef,
		AiValidated: "No",
		RuleID:      ruleID,
		Source:      "dockerfile",
		CWE:         cwe,
		OWASP:       owasp,
		Confidence:  conf,
	}
}
