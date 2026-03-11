package utils

import (
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

type RAMInfo struct {
	TotalGB     float64
	AvailableGB float64
	TotalMB     int
	AvailableMB int
}

func GetSystemRAM() (*RAMInfo, error) {
	ram := &RAMInfo{
		TotalGB:     8.0,
		AvailableGB: 4.0,
		TotalMB:     8192,
		AvailableMB: 4096,
	}

	var err error

	switch runtime.GOOS {
	case "windows":
		err = getRAMWindows(ram)
	case "darwin":
		err = getRAMDarwin(ram)
	default: // linux, freebsd, etc
		err = getRAMLinux(ram)
	}

	// Calculate GBs if we got MBs successfully but didn't calculate GBs
	if err == nil && ram.TotalMB > 0 {
		ram.TotalGB = float64(ram.TotalMB) / 1024.0
		ram.AvailableGB = float64(ram.AvailableMB) / 1024.0
	} else if err != nil {
		// Just return safe defaults on failure
		return ram, nil // Don't return error to prevent panic/crash
	}

	return ram, nil
}

func getRAMWindows(ram *RAMInfo) error {
	// wmic OS get FreePhysicalMemory,TotalVisibleMemorySize /Value
	cmd := exec.Command("wmic", "OS", "get", "FreePhysicalMemory,TotalVisibleMemorySize", "/Value")
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	lines := strings.Split(NormalizeNewlines(string(output)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "TotalVisibleMemorySize=") {
			val := strings.TrimPrefix(line, "TotalVisibleMemorySize=")
			kb, _ := strconv.ParseInt(strings.TrimSpace(val), 10, 64)
			ram.TotalMB = int(kb / 1024)
		} else if strings.HasPrefix(line, "FreePhysicalMemory=") {
			val := strings.TrimPrefix(line, "FreePhysicalMemory=")
			kb, _ := strconv.ParseInt(strings.TrimSpace(val), 10, 64)
			ram.AvailableMB = int(kb / 1024)
		}
	}
	return nil
}

func getRAMDarwin(ram *RAMInfo) error {
	// Total RAM: sysctl -n hw.memsize
	cmdTotal := exec.Command("sysctl", "-n", "hw.memsize")
	outTotal, err := cmdTotal.Output()
	if err == nil {
		bytes, _ := strconv.ParseInt(strings.TrimSpace(string(outTotal)), 10, 64)
		ram.TotalMB = int(bytes / 1024 / 1024)
	}

	// Available RAM: vm_stat
	cmdFree := exec.Command("vm_stat")
	outFree, err := cmdFree.Output()
	if err != nil {
		return err
	}

	pageSize := int64(4096) // Default page size
	var freePages, inactivePages int64

	lines := strings.Split(NormalizeNewlines(string(outFree)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Pages free:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				val := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(parts[1]), "."))
				freePages, _ = strconv.ParseInt(val, 10, 64)
			}
		} else if strings.HasPrefix(line, "Pages inactive:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				val := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(parts[1]), "."))
				inactivePages, _ = strconv.ParseInt(val, 10, 64)
			}
		}
	}

	ram.AvailableMB = int(((freePages + inactivePages) * pageSize) / 1024 / 1024)
	return nil
}

func getRAMLinux(ram *RAMInfo) error {
	cmd := exec.Command("grep", "-E", "^(MemTotal|MemAvailable):", "/proc/meminfo")
	output, err := cmd.Output()
	if err != nil {
		// Fallback to free -m
		cmd = exec.Command("free", "-m")
		output, err = cmd.Output()
		if err != nil {
			return err
		}
		lines := strings.Split(NormalizeNewlines(string(output)), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Mem:") {
				fields := strings.Fields(line)
				if len(fields) >= 7 {
					ram.TotalMB, _ = strconv.Atoi(fields[1])
					ram.AvailableMB, _ = strconv.Atoi(fields[6])
					return nil
				}
			}
		}
	} else {
		lines := strings.Split(NormalizeNewlines(string(output)), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				value, _ := strconv.Atoi(fields[1])
				switch fields[0] {
				case "MemTotal:":
					ram.TotalMB = value / 1024
				case "MemAvailable:":
					ram.AvailableMB = value / 1024
				}
			}
		}
	}
	return nil
}
