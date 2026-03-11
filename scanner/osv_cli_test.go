package scanner

import (
	"runtime"
	"testing"
)

func TestGetOSVBin(t *testing.T) {
	result := getOSVBin()

	switch runtime.GOOS {
	case "windows":
		if result != "osv-scanner.exe" {
			t.Errorf("getOSVBin() on Windows = %q, want %q", result, "osv-scanner.exe")
		}
	default:
		if result != "osv-scanner" {
			t.Errorf("getOSVBin() on %s = %q, want %q", runtime.GOOS, result, "osv-scanner")
		}
	}
}
