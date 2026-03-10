package reporter

import "strings"

// Finding represents a detected vulnerability
type Finding struct {
	SrNo        int
	IssueName   string
	FilePath    string
	Description string
	Severity    string
	LineNumber  string
	AiValidated string
	Remediation string
	RuleID      string
	Source      string  // "custom", "semgrep", "ai-discovery", "taint-analyzer", "ast", "secret"
	CWE         string  // CWE ID (e.g., "CWE-79")
	OWASP       string  // OWASP category (e.g., "A03:2021")
	Confidence  float64 // 0.0-1.0 confidence score
	CodeSnippet string  // Source code around the vulnerable line
	ExploitPoC  string  // AI-generated proof of concept exploit
	FixedCode   string  // AI-generated fixed code snippet
}

// IsFalsePositive returns true if the AI validator marked this finding as a false positive
func (f Finding) IsFalsePositive() bool {
	lower := strings.ToLower(f.AiValidated)
	return strings.Contains(lower, "false positive")
}

// SplitFindings separates findings into confirmed (true positives) and false positives
func SplitFindings(findings []Finding) (confirmed, falsePositives []Finding) {
	for _, f := range findings {
		if f.IsFalsePositive() {
			falsePositives = append(falsePositives, f)
		} else {
			confirmed = append(confirmed, f)
		}
	}
	return
}
