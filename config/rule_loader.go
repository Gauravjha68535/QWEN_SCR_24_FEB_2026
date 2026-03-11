package config

import (
	"QWEN_SCR_24_FEB_2026/utils"
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Rule represents a single vulnerability pattern
type Rule struct {
	ID        string   `yaml:"id"`
	Languages []string `yaml:"languages"`
	Patterns  []struct {
		Regex         string         `yaml:"regex"`
		CompiledRegex *regexp.Regexp `yaml:"-"` // Added for performance (ignored by yaml)
	} `yaml:"patterns"`
	Severity    string  `yaml:"severity"`
	Description string  `yaml:"description"`
	Remediation string  `yaml:"remediation"`
	CWE         string  `yaml:"cwe"`
	OWASP       string  `yaml:"owasp"`
	Confidence  float64 `yaml:"confidence"`
}

// flexRule is a more tolerant intermediate representation that handles
// both map and list formats for "patterns", plus a singular "pattern" key.
type flexRule struct {
	ID          string      `yaml:"id"`
	Languages   []string    `yaml:"languages"`
	Patterns    interface{} `yaml:"patterns"` // can be a list or a map
	Pattern     string      `yaml:"pattern"`  // some files use singular "pattern"
	Severity    string      `yaml:"severity"`
	Description string      `yaml:"description"`
	Remediation string      `yaml:"remediation"`
	CWE         string      `yaml:"cwe"`
	OWASP       string      `yaml:"owasp"`
	Confidence  float64     `yaml:"confidence"`
}

// normalizeRule converts a flexRule to a strict Rule
func normalizeRule(fr flexRule) Rule {
	r := Rule{
		ID:          fr.ID,
		Languages:   fr.Languages,
		Severity:    fr.Severity,
		Description: fr.Description,
		Remediation: fr.Remediation,
		CWE:         fr.CWE,
		OWASP:       fr.OWASP,
		Confidence:  fr.Confidence,
	}

	switch p := fr.Patterns.(type) {
	case []interface{}:
		// Standard list format: patterns: [- regex: "..."]
		for _, item := range p {
			if m, ok := item.(map[string]interface{}); ok {
				if regexVal, ok := m["regex"].(string); ok {
					r.Patterns = append(r.Patterns, struct {
						Regex         string         `yaml:"regex"`
						CompiledRegex *regexp.Regexp `yaml:"-"`
					}{Regex: regexVal})
				}
			}
		}
	case map[string]interface{}:
		// Map format: patterns: {regex: "..."}
		if regexVal, ok := p["regex"].(string); ok {
			r.Patterns = append(r.Patterns, struct {
				Regex         string         `yaml:"regex"`
				CompiledRegex *regexp.Regexp `yaml:"-"`
			}{Regex: regexVal})
		}
	case string:
		// Single string format: patterns: "some_regex"
		r.Patterns = append(r.Patterns, struct {
			Regex         string         `yaml:"regex"`
			CompiledRegex *regexp.Regexp `yaml:"-"`
		}{Regex: p})
	}

	// Fallback: if "pattern" (singular) was used
	if len(r.Patterns) == 0 && fr.Pattern != "" {
		r.Patterns = append(r.Patterns, struct {
			Regex         string         `yaml:"regex"`
			CompiledRegex *regexp.Regexp `yaml:"-"`
		}{Regex: fr.Pattern})
	}

	return r
}

// LoadRulesFile loads rules from a single YAML file with maximum tolerance
func LoadRulesFile(filePath string) ([]Rule, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var rules []Rule

	// === Strategy 1: Try strict parsing as []Rule ===
	if err := yaml.Unmarshal(data, &rules); err == nil {
		return compilePatterns(rules), nil
	}

	// === Strategy 2: Try flexible parsing as []flexRule ===
	var flexRules []flexRule
	if err := yaml.Unmarshal(data, &flexRules); err == nil {
		for _, fr := range flexRules {
			if fr.ID != "" {
				rules = append(rules, normalizeRule(fr))
			}
		}
		if len(rules) > 0 {
			return compilePatterns(rules), nil
		}
	}

	// === Strategy 3: Split file into individual YAML documents and parse each ===
	// This handles files where some rules are valid and others have syntax errors.
	rules = parseRulesLineByLine(data, filePath)
	if len(rules) > 0 {
		return compilePatterns(rules), nil
	}

	return nil, fmt.Errorf("failed to parse rule YAML (%s): no valid rules found", filepath.Base(filePath))
}

// parseRulesLineByLine splits YAML content at "- id:" boundaries and
// parses each rule individually. This rescues valid rules from files
// that contain some broken rules.
func parseRulesLineByLine(data []byte, filePath string) []Rule {
	var rules []Rule
	content := string(data)

	scanner := bufio.NewScanner(strings.NewReader(content))
	var currentChunk strings.Builder
	inRule := false
	baseName := filepath.Base(filePath)
	totalBroken := 0

	for scanner.Scan() {
		line := scanner.Text()

		// Detect start of new rule: "- id:"
		if strings.HasPrefix(strings.TrimSpace(line), "- id:") {
			// Process previous chunk if exists
			if inRule && currentChunk.Len() > 0 {
				parsed := tryParseChunk(currentChunk.String())
				if parsed != nil {
					rules = append(rules, *parsed)
				} else {
					totalBroken++
				}
			}
			currentChunk.Reset()
			inRule = true
		}

		if inRule {
			currentChunk.WriteString(line)
			currentChunk.WriteString("\n")
		}
	}

	// Process last chunk
	if inRule && currentChunk.Len() > 0 {
		parsed := tryParseChunk(currentChunk.String())
		if parsed != nil {
			rules = append(rules, *parsed)
		} else {
			totalBroken++
		}
	}

	if totalBroken > 0 {
		utils.LogWarn(fmt.Sprintf("  %s: rescued %d rules, %d rules had syntax errors (skipped)",
			baseName, len(rules), totalBroken))
	}

	return rules
}

// tryParseChunk attempts to parse a single YAML rule chunk
func tryParseChunk(chunk string) *Rule {
	// Try strict first
	var rules []Rule
	if err := yaml.Unmarshal([]byte(chunk), &rules); err == nil && len(rules) > 0 {
		return &rules[0]
	}

	// Try flexible
	var flexRules []flexRule
	if err := yaml.Unmarshal([]byte(chunk), &flexRules); err == nil && len(flexRules) > 0 {
		r := normalizeRule(flexRules[0])
		return &r
	}

	return nil
}

// compilePatterns pre-compiles regexes for all rules
func compilePatterns(rules []Rule) []Rule {
	for i := range rules {
		for j := range rules[i].Patterns {
			if rules[i].Patterns[j].Regex != "" {
				r, _ := regexp.Compile(rules[i].Patterns[j].Regex)
				rules[i].Patterns[j].CompiledRegex = r
			}
		}
	}
	return rules
}

// LoadRules loads all .yaml rule files from the rules directory (including subdirectories)
func LoadRules(rulesDir string) ([]Rule, error) {
	var allRules []Rule

	err := filepath.Walk(rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			utils.LogError(fmt.Sprintf("Error accessing path %s", path), err)
			return nil // continue walking
		}
		if info.IsDir() || filepath.Ext(info.Name()) != ".yaml" {
			return nil
		}

		rules, err := LoadRulesFile(path)
		if err != nil {
			utils.LogError(fmt.Sprintf("Failed to parse rule YAML (%s)", info.Name()), err)
			return nil // continue walking
		}

		allRules = append(allRules, rules...)
		utils.LogInfo(fmt.Sprintf("Loaded %d rules from %s", len(rules), info.Name()))
		return nil
	})
	if err != nil {
		return nil, err
	}

	return allRules, nil
}
