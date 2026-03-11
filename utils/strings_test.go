package utils

import "testing"

func TestNormalizeNewlines(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Unix newlines pass through unchanged", "line1\nline2\nline3", "line1\nline2\nline3"},
		{"Windows CRLF converted to LF", "line1\r\nline2\r\nline3", "line1\nline2\nline3"},
		{"Classic Mac CR converted to LF", "line1\rline2\rline3", "line1\nline2\nline3"},
		{"Mixed newlines all converted to LF", "line1\r\nline2\rline3\nline4", "line1\nline2\nline3\nline4"},
		{"Empty string returns empty", "", ""},
		{"No newlines returns unchanged", "single-line-content", "single-line-content"},
		{"Trailing CRLF handled", "hello\r\n", "hello\n"},
		{"Multiple consecutive CRLFs", "a\r\n\r\nb", "a\n\nb"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeNewlines(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizeNewlines(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGetLanguage(t *testing.T) {
	tests := []struct {
		ext      string
		expected string
	}{
		{".go", "go"},
		{".py", "python"},
		{".js", "javascript"},
		{".ts", "typescript"},
		{".java", "java"},
		{".php", "php"},
		{".rb", "ruby"},
		{".rs", "rust"},
		{".cs", "csharp"},
		{".kt", "kotlin"},
		{".swift", "swift"},
		{".sol", "solidity"},
		{".xyz", "unknown"},
		{"", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.ext, func(t *testing.T) {
			result := GetLanguage(tt.ext)
			if result != tt.expected {
				t.Errorf("GetLanguage(%q) = %q, want %q", tt.ext, result, tt.expected)
			}
		})
	}
}
