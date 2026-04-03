package ai

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"SentryQ/reporter"
)

// FPHistory stores historical false positive data
type FPHistory struct {
	Findings      []FindingFeedback `json:"findings"`
	LastUpdated   string            `json:"last_updated"`
	TotalFeedback int               `json:"total_feedback"`
}

// FindingFeedback stores user feedback on a finding
type FindingFeedback struct {
	FindingID       string    `json:"finding_id"`
	RuleID          string    `json:"rule_id"`
	FilePath        string    `json:"file_path"`
	Severity        string    `json:"severity"`
	IsFalsePositive bool      `json:"is_false_positive"`
	FeedbackDate    time.Time `json:"feedback_date"`
	Comments        string    `json:"comments"`
}

// MLFPReducer performs machine learning-based false positive reduction.
// All exported methods are safe for concurrent use.
type MLFPReducer struct {
	mu          sync.Mutex
	history     *FPHistory
	historyFile string
}

// NewMLFPReducer creates a new ML false positive reducer
func NewMLFPReducer(cacheDir string) *MLFPReducer {
	return &MLFPReducer{
		history: &FPHistory{
			Findings:    make([]FindingFeedback, 0),
			LastUpdated: time.Now().Format(time.RFC3339),
		},
		historyFile: filepath.Join(cacheDir, ".fp-history.json"),
	}
}

// LoadHistory loads historical feedback data
func (ml *MLFPReducer) LoadHistory() error {
	ml.mu.Lock()
	defer ml.mu.Unlock()

	data, err := os.ReadFile(ml.historyFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No history file yet
		}
		return err
	}

	return json.Unmarshal(data, &ml.history)
}

// SaveHistory saves historical feedback data
func (ml *MLFPReducer) SaveHistory() error {
	ml.mu.Lock()
	defer ml.mu.Unlock()

	ml.history.LastUpdated = time.Now().Format(time.RFC3339)
	ml.history.TotalFeedback = len(ml.history.Findings)

	data, err := json.MarshalIndent(ml.history, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(ml.historyFile, data, 0600)
}

// FilterFindingsByFPProbability filters findings based on FP probability.
// Findings whose historical FP probability meets or exceeds threshold are dropped.
func (ml *MLFPReducer) FilterFindingsByFPProbability(findings []reporter.Finding, threshold float64) []reporter.Finding {
	ml.mu.Lock()
	defer ml.mu.Unlock()

	var filtered []reporter.Finding

	for _, finding := range findings {
		fpProb := ml.calculateFPProbabilityLocked(finding)

		// If FP probability is below threshold, keep the finding
		if fpProb < threshold {
			if fpProb > 0.0 {
				finding.Description = fmt.Sprintf("%s [ML FP Probability: %.1f%%]",
					finding.Description, fpProb*100)
			}
			filtered = append(filtered, finding)
		}
	}

	return filtered
}

// calculateFPProbabilityLocked calculates the probability that a finding is a false positive.
// Caller must hold ml.mu.
func (ml *MLFPReducer) calculateFPProbabilityLocked(finding reporter.Finding) float64 {
	if len(ml.history.Findings) == 0 {
		return 0.0 // No history, default to 0% FP (assume true positive)
	}

	// Find similar historical findings
	similarFindings := ml.findSimilarFindingsLocked(finding)

	if len(similarFindings) < 3 {
		return 0.0 // Not enough similar findings for a confident prediction
	}

	// Calculate FP rate from similar findings
	fpCount := 0
	for _, f := range similarFindings {
		if f.IsFalsePositive {
			fpCount++
		}
	}

	return float64(fpCount) / float64(len(similarFindings))
}

// findSimilarFindingsLocked finds historically similar findings.
// Caller must hold ml.mu.
func (ml *MLFPReducer) findSimilarFindingsLocked(current reporter.Finding) []FindingFeedback {
	var similar []FindingFeedback

	for _, feedback := range ml.history.Findings {
		score := ml.calculateSimilarityScore(current, feedback)
		if score > 0.8 { // 80% similarity threshold
			similar = append(similar, feedback)
		}
	}

	return similar
}

// calculateSimilarityScore calculates similarity between current and historical finding
func (ml *MLFPReducer) calculateSimilarityScore(current reporter.Finding, historical FindingFeedback) float64 {
	score := 0.0
	maxScore := 4.0

	// Rule ID match (most important)
	if current.RuleID == historical.RuleID {
		score += 2.0
	} else if strings.Contains(current.RuleID, historical.RuleID) ||
		strings.Contains(historical.RuleID, current.RuleID) {
		score += 1.0
	}

	// Severity match
	if current.Severity == historical.Severity {
		score += 1.0
	}

	// File extension match
	currentExt := getFileExtension(current.FilePath)
	historicalExt := getFileExtension(historical.FilePath)
	if currentExt == historicalExt {
		score += 1.0
	}

	return score / maxScore
}

// Helper functions
func getFileExtension(filePath string) string {
	ext := filepath.Ext(filePath)
	if ext == "" {
		return "unknown"
	}
	return strings.TrimPrefix(ext, ".")
}
