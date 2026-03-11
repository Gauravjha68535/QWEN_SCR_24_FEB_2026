package utils

import "strings"

// NormalizeNewlines safely converts Windows "\r\n" and classic macOS "\r" to standard Unix "\n".
// This prevents cross-platform parsing issues in String matching and AI prompt payloads.
func NormalizeNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return s
}
