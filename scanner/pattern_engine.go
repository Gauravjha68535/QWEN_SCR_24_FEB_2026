package scanner

import (
	"QWEN_SCR_24_FEB_2026/config"
	"QWEN_SCR_24_FEB_2026/reporter"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"
	"sync/atomic"
)

// scanJob represents a single file scanning job for the worker pool
type scanJob struct {
	filePath string
	rules    []config.Rule
}

// scanResult represents results from a single file scan
type scanResult struct {
	findings []reporter.Finding
}

// getDefaultConfidence returns a default confidence score based on severity
// Rules with explicit confidence in YAML will override this
func getDefaultConfidence(severity string) float64 {
	switch severity {
	case "critical":
		return 0.95
	case "high":
		return 0.85
	case "medium":
		return 0.70
	case "low":
		return 0.50
	case "info":
		return 0.40
	default:
		return 0.60
	}
}

// detectFrameworks reads a subset of files to guess which frameworks are in use
func detectFrameworks(result *ScanResult) []string {
	frameworksFound := make(map[string]bool)

	// Quick check of package.json, requirements.txt, pom.xml, composer.json, etc.
	for _, files := range result.FilePaths {
		for _, file := range files {
			fileName := file
			content, err := os.ReadFile(fileName)
			if err != nil {
				continue
			}
			source := string(content)

			if regexp.MustCompile(`(?i)(django)`).MatchString(source) {
				frameworksFound["django"] = true
			}
			if regexp.MustCompile(`(?i)(flask)`).MatchString(source) {
				frameworksFound["flask"] = true
			}
			if regexp.MustCompile(`(?i)(fastapi|from\s+fastapi)`).MatchString(source) {
				frameworksFound["fastapi"] = true
			}
			if regexp.MustCompile(`(?i)(express)`).MatchString(source) {
				frameworksFound["express"] = true
			}
			if regexp.MustCompile(`(?i)(org\.springframework)`).MatchString(source) {
				frameworksFound["spring"] = true
			}
			if regexp.MustCompile(`(?i)(illuminate|laravel)`).MatchString(source) {
				frameworksFound["laravel"] = true
			}
			if regexp.MustCompile(`(?i)(rails|activerecord)`).MatchString(source) {
				frameworksFound["rails"] = true
			}
			if regexp.MustCompile(`(?i)(@angular/core|angular\.module)`).MatchString(source) {
				frameworksFound["angular"] = true
			}
			if regexp.MustCompile(`(?i)(next/app|next/router|next\.config)`).MatchString(source) {
				frameworksFound["next_js"] = true
			}
			if regexp.MustCompile(`(?i)(nuxt\.config|@nuxt/|useNuxtApp)`).MatchString(source) {
				frameworksFound["nuxt_js"] = true
			}
			if regexp.MustCompile(`(?i)(svelte|\.svelte)`).MatchString(source) {
				frameworksFound["svelte"] = true
			}
		}
	}

	var frameworks []string
	for f := range frameworksFound {
		frameworks = append(frameworks, f)
	}
	return frameworks
}

// frameworkFileMap maps detected framework names to their actual YAML filenames
// This handles case sensitivity (e.g., "angular" -> "Angular.yaml")
var frameworkFileMap = map[string]string{
	"django":  "django.yaml",
	"flask":   "flask.yaml",
	"fastapi": "fastapi.yaml",
	"express": "express.yaml",
	"spring":  "spring.yaml",
	"laravel": "laravel.yaml",
	"rails":   "rails.yaml",
	"angular": "Angular.yaml",
	"next_js": "Next_js.yaml",
	"nuxt_js": "Nuxt_js.yaml",
	"svelte":  "svelte.yaml",
}

// RunPatternScan performs multi-threaded pattern scanning across all files
func RunPatternScan(result *ScanResult, baseRules []config.Rule, rulesDir string) []reporter.Finding {
	// Detect frameworks and load specific rules
	detectedFrameworks := detectFrameworks(result)
	rules := append([]config.Rule(nil), baseRules...) // Copy base rules

	for _, framework := range detectedFrameworks {
		fileName, ok := frameworkFileMap[framework]
		if !ok {
			fileName = framework + ".yaml"
		}
		frameworkRulePath := filepath.Join(rulesDir, "frameworks", fileName)
		frameworkRules, err := config.LoadRulesFile(frameworkRulePath)
		if err == nil && len(frameworkRules) > 0 {
			rules = append(rules, frameworkRules...)
		}
	}
	// Pre-group rules by language for faster lookup
	rulesByLang := make(map[string][]config.Rule)
	for _, rule := range rules {
		for _, lang := range rule.Languages {
			rulesByLang[lang] = append(rulesByLang[lang], rule)
		}
	}

	// Collect all scanning jobs
	var jobs []scanJob
	for lang, files := range result.FilePaths {
		applicableRules, ok := rulesByLang[lang]
		if !ok || len(applicableRules) == 0 {
			continue
		}
		for _, filePath := range files {
			jobs = append(jobs, scanJob{
				filePath: filePath,
				rules:    applicableRules,
			})
		}
	}

	if len(jobs) == 0 {
		return nil
	}

	// Determine worker count (use CPU cores, min 2, max 8)
	numWorkers := runtime.NumCPU()
	if numWorkers < 2 {
		numWorkers = 2
	}
	if numWorkers > 8 {
		numWorkers = 8
	}
	if numWorkers > len(jobs) {
		numWorkers = len(jobs)
	}

	// Channel for jobs and results
	jobChan := make(chan scanJob, len(jobs))
	resultChan := make(chan scanResult, len(jobs))

	// Atomic counter for Sr numbers
	var srCounter int64

	// Start workers
	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobChan {
				findings := scanFile(job.filePath, job.rules, &srCounter)
				resultChan <- scanResult{findings: findings}
			}
		}()
	}

	// Send jobs
	for _, job := range jobs {
		jobChan <- job
	}
	close(jobChan)

	// Wait for completion and close results
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect all findings
	var allFindings []reporter.Finding
	for res := range resultChan {
		allFindings = append(allFindings, res.findings...)
	}

	// Re-number findings sequentially
	for i := range allFindings {
		allFindings[i].SrNo = i + 1
	}

	return allFindings
}

// scanFile scans a single file against all applicable rules
func scanFile(filePath string, rules []config.Rule, counter *int64) []reporter.Finding {
	// Contextual Filtering 1: Skip test/mock files to reduce false positives
	if IsTestFile(filePath) {
		return nil
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}
	originalSource := string(content)

	// Contextual Filtering 2: Strip comments to avoid matching commented-out vulns
	ext := filepath.Ext(filePath)
	// We matched the file extension in helpers.go
	cleanSource := StripComments(originalSource, ext)

	var findings []reporter.Finding
	for _, rule := range rules {
		for _, pattern := range rule.Patterns {
			if pattern.CompiledRegex == nil {
				continue
			}

			// Search against the clean source (comments replaced by spaces)
			matches := pattern.CompiledRegex.FindAllStringIndex(cleanSource, -1)
			for _, match := range matches {
				// We can still use originalSource or cleanSource for countLines
				// since the length and newlines are identical!
				startLine := countLines(originalSource[:match[0]]) + 1
				endLine := countLines(originalSource[:match[1]]) + 1

				lineRef := formatLineRef(startLine, endLine)

				// Determine confidence score
				confidence := rule.Confidence
				if confidence == 0 {
					confidence = getDefaultConfidence(rule.Severity)
				}

				srNo := int(atomic.AddInt64(counter, 1))

				findings = append(findings, reporter.Finding{
					SrNo:        srNo,
					IssueName:   rule.ID,
					FilePath:    filePath,
					Description: rule.Description,
					Severity:    rule.Severity,
					LineNumber:  lineRef,
					AiValidated: "No",
					Remediation: rule.Remediation,
					RuleID:      rule.ID,
					Source:      "custom",
					CWE:         rule.CWE,
					OWASP:       rule.OWASP,
					Confidence:  confidence,
				})
			}
		}
	}

	return findings
}
