package scanner

import (
	"testing"
)

func TestComputeLevenshteinDistance(t *testing.T) {
	tests := []struct {
		name     string
		s1       string
		s2       string
		expected int
	}{
		{
			name:     "identical strings",
			s1:       "react",
			s2:       "react",
			expected: 0,
		},
		{
			name:     "one character difference (substitution)",
			s1:       "reacct",
			s2:       "react",
			expected: 1,
		},
		{
			name:     "one character difference (deletion)",
			s1:       "rect",
			s2:       "react",
			expected: 1,
		},
		{
			name:     "one character difference (insertion)",
			s1:       "reactt",
			s2:       "react",
			expected: 1,
		},
		{
			name:     "two character difference",
			s1:       "reqeusts",
			s2:       "requests",
			expected: 2,
		},
		{
			name:     "completely different strings",
			s1:       "apple",
			s2:       "banana",
			expected: 5,
		},
		{
			name:     "empty s1",
			s1:       "",
			s2:       "react",
			expected: 5,
		},
		{
			name:     "empty s2",
			s1:       "react",
			s2:       "",
			expected: 5,
		},
		{
			name:     "both empty",
			s1:       "",
			s2:       "",
			expected: 0,
		},
		{
			name:     "number substitution",
			s1:       "l0dash",
			s2:       "lodash",
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := computeLevenshteinDistance(tt.s1, tt.s2)
			if result != tt.expected {
				t.Errorf("computeLevenshteinDistance(%q, %q) = %d; want %d", tt.s1, tt.s2, result, tt.expected)
			}
		})
	}
}
