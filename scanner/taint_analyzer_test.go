package scanner

import "testing"

func TestIsTestFilePath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		// Unix-style paths
		{"Go test file (unix)", "/app/user_test.go", true},
		{"Python test file (unix)", "/app/user_test.py", true},
		{"JS test file (unix)", "/app/user.test.js", true},
		{"TS spec file (unix)", "/app/user.spec.ts", true},
		{"Test directory (unix)", "/app/test/utils.go", true},
		{"Tests directory (unix)", "/app/tests/utils.go", true},
		{"__tests__ directory (unix)", "/app/__tests__/utils.js", true},
		{"Mock directory (unix)", "/app/mock/client.go", true},
		{"Mocks directory (unix)", "/app/mocks/client.go", true},
		{"Fixture directory (unix)", "/app/fixture/data.json", true},
		{"Fixtures directory (unix)", "/app/fixtures/data.json", true},
		{"__mocks__ directory (unix)", "/app/__mocks__/api.js", true},
		{"Testdata directory (unix)", "/app/testdata/input.txt", true},
		{"Spec directory (unix)", "/app/spec/feature.rb", true},
		{"Specs directory (unix)", "/app/specs/feature.rb", true},
		{"Normal source file (unix)", "/app/src/main.go", false},
		{"Normal controller (unix)", "/app/controllers/user.py", false},

		// Windows-style paths (backslashes)
		{"Go test file (windows)", `C:\project\user_test.go`, true},
		{"Test directory (windows)", `C:\project\test\utils.go`, true},
		{"Tests directory (windows)", `C:\project\tests\utils.go`, true},
		{"Mock directory (windows)", `C:\project\mock\client.go`, true},
		{"Fixture directory (windows)", `C:\project\fixture\data.json`, true},
		{"__tests__ directory (windows)", `C:\project\__tests__\utils.js`, true},
		{"Normal source file (windows)", `C:\project\src\main.go`, false},
		{"Normal controller (windows)", `C:\project\controllers\user.py`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isTestFilePath(tt.path)
			if result != tt.expected {
				t.Errorf("isTestFilePath(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}
