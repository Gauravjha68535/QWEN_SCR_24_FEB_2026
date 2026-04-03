package utils

import "strings"

// NormalizeNewlines safely converts Windows "\r\n" and classic macOS "\r" to standard Unix "\n".
// This prevents cross-platform parsing issues in String matching and AI prompt payloads.
func NormalizeNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return s
}

// TruncateString truncates s to at most maxLen Unicode code points, appending "..." if cut.
// Using rune-based slicing prevents splitting multi-byte UTF-8 characters.
func TruncateString(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}
