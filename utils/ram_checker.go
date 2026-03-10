package utils

import (
	"os/exec"
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
	ram := &RAMInfo{}

	cmd := exec.Command("grep", "-E", "^(MemTotal|MemAvailable):", "/proc/meminfo")
	output, err := cmd.Output()
	if err != nil {
		cmd = exec.Command("free", "-m")
		output, err = cmd.Output()
		if err != nil {
			return nil, err
		}
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Mem:") {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					ram.TotalMB, _ = strconv.Atoi(fields[1])
					ram.AvailableMB, _ = strconv.Atoi(fields[6])
					break
				}
			}
		}
	} else {
		lines := strings.Split(string(output), "\n")
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

	ram.TotalGB = float64(ram.TotalMB) / 1024
	ram.AvailableGB = float64(ram.AvailableMB) / 1024

	return ram, nil
}
