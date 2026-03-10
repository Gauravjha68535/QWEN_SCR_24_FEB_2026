package config

import (
	"QWEN_SCR_24_FEB_2026/utils"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

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

// LoadRulesFile loads rules from a single YAML file
func LoadRulesFile(filePath string) ([]Rule, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var rules []Rule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		// If that fails, try as a single rule
		var singleRule Rule
		if err2 := yaml.Unmarshal(data, &singleRule); err2 != nil {
			return nil, fmt.Errorf("failed to parse rule YAML (%s): %w", filepath.Base(filePath), err)
		}
		rules = append(rules, singleRule)
	}

	// Pre-compile regexes for massive performance boost during scanning
	for i := range rules {
		for j := range rules[i].Patterns {
			if rules[i].Patterns[j].Regex != "" {
				// We ignore the error here; if a regex is totally invalid,
				// CompiledRegex just remains nil and we skip it later.
				r, _ := regexp.Compile(rules[i].Patterns[j].Regex)
				rules[i].Patterns[j].CompiledRegex = r
			}
		}
	}

	return rules, nil
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
