package scanner

import (
	"runtime"
	"testing"
)

func TestGetSemgrepBin(t *testing.T) {
	result := getSemgrepBin()

	switch runtime.GOOS {
	case "windows":
		if result != "semgrep.exe" {
			t.Errorf("getSemgrepBin() on Windows = %q, want %q", result, "semgrep.exe")
		}
	default:
		if result != "semgrep" {
			t.Errorf("getSemgrepBin() on %s = %q, want %q", runtime.GOOS, result, "semgrep")
		}
	}
}

func TestMapSemgrepSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"error", "critical"},
		{"critical", "critical"},
		{"warning", "high"},
		{"high", "high"},
		{"info", "medium"},
		{"medium", "medium"},
		{"low", "low"},
		{"unknown", "medium"},
		{"", "medium"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := mapSemgrepSeverity(tt.input)
			if result != tt.expected {
				t.Errorf("mapSemgrepSeverity(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
