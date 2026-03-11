package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"QWEN_SCR_24_FEB_2026/ai"
	"QWEN_SCR_24_FEB_2026/config"
	"QWEN_SCR_24_FEB_2026/scanner"
	"QWEN_SCR_24_FEB_2026/utils"

	"github.com/fatih/color"
)

// ScanConfig holds user-selected scan options via menu
type ScanConfig struct {
	TargetDir             string
	RulesDir              string
	EnableAI              bool
	EnableAIDiscovery     bool
	EnableStaticPlusAI    bool // Run static engine + AI discovery + AI validation
	EnableAIConsolidation bool // New: Run both, save to DB, and merge using AI
	EnableSemgrep         bool
	EnableDependencyScan  bool
	EnableSecretDetection bool
	EnableContainerScan   bool
	EnableSupplyChain     bool
	EnableCompliance      bool
	EnableThreatIntel     bool
	EnableSymbolicExec    bool
	EnableMLFPReduction   bool
	EnableWebDashboard    bool
	ModelName             string
	OllamaHost            string
	OutputCSV             string
	OutputHTML            string
	OutputPDF             string
	ComplianceFrameworks  []string
}

// ShowMainMenu displays the interactive configuration menu
func ShowMainMenu() *ScanConfig {
	var config *ScanConfig
	if savedCfg, ok := loadSavedConfig(); ok {
		config = savedCfg
	} else {
		config = &ScanConfig{
			RulesDir:              "rules",
			EnableSemgrep:         true,
			EnableDependencyScan:  true,
			EnableSecretDetection: true,
			EnableContainerScan:   true,
			OutputCSV:             "report.csv",
			OutputHTML:            "report.html",
			OutputPDF:             "report.pdf",
			ComplianceFrameworks:  []string{},
			ModelName:             ai.GetDefaultModel(),
			OllamaHost:            "localhost:11434",
		}
	}

	reader := bufio.NewReader(os.Stdin)

	for {
		utils.PrintBanner()

		fmt.Println()
		color.Cyan("═══════════════════════════════════════════════════════")
		color.White("              🎯 SCAN CONFIGURATION MENU")
		color.Cyan("═══════════════════════════════════════════════════════")
		fmt.Println()

		// Show current configuration
		showCurrentConfig(config)

		fmt.Println()
		color.Green("📋 Menu Options:")
		fmt.Println("  1.  Set Target Directory")
		fmt.Println("  2.  Configure AI Mode (Validation / Discovery)")
		fmt.Println("  3.  Toggle Semgrep Scanning")
		fmt.Println("  4.  Toggle Dependency Scanning")
		fmt.Println("  5.  Toggle Secret Detection")
		fmt.Println("  6.  Toggle Supply Chain Security (SBOM)")
		fmt.Println("  7.  Toggle Compliance Checking")
		fmt.Println("  8.  Toggle Threat Intelligence")
		fmt.Println("  9.  Toggle Taint / Data Flow Analysis")
		fmt.Println("  10. Toggle ML FP Reduction")
		fmt.Println("  11. Toggle Web Dashboard API")
		fmt.Println("  12. Toggle Container Image Scanning")
		fmt.Println("  13. Set AI Model")
		fmt.Println("  14. Set Output Files")
		fmt.Println("  15. Configure Compliance Frameworks")
		fmt.Println("  16. Set Ollama Host (Remote AI)")
		fmt.Println("  17. 🛠️  SYSTEM DIAGNOSTIC (Verify Environment)")
		fmt.Println("  18. 🚀 START SCAN")
		fmt.Println("  0.  Exit")
		fmt.Println()

		fmt.Print(color.HiYellowString("Enter your choice (0-17): "))
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			setTargetDirectory(reader, config)
		case "2":
			configureAIMode(reader, config)
		case "3":
			config.EnableSemgrep = !config.EnableSemgrep
			color.Green("✓ Semgrep Scanning: %v", config.EnableSemgrep)
		case "4":
			config.EnableDependencyScan = !config.EnableDependencyScan
			color.Green("✓ Dependency Scanning: %v", config.EnableDependencyScan)
		case "5":
			config.EnableSecretDetection = !config.EnableSecretDetection
			color.Green("✓ Secret Detection: %v", config.EnableSecretDetection)
		case "6":
			config.EnableSupplyChain = !config.EnableSupplyChain
			color.Green("✓ Supply Chain Security: %v", config.EnableSupplyChain)
		case "7":
			config.EnableCompliance = !config.EnableCompliance
			color.Green("✓ Compliance Checking: %v", config.EnableCompliance)
		case "8":
			config.EnableThreatIntel = !config.EnableThreatIntel
			color.Green("✓ Threat Intelligence: %v", config.EnableThreatIntel)
		case "9":
			config.EnableSymbolicExec = !config.EnableSymbolicExec
			color.Green("✓ Taint / Data Flow Analysis: %v", config.EnableSymbolicExec)
		case "10":
			config.EnableMLFPReduction = !config.EnableMLFPReduction
			color.Green("✓ ML FP Reduction: %v", config.EnableMLFPReduction)
		case "11":
			config.EnableWebDashboard = !config.EnableWebDashboard
			color.Green("✓ Web Dashboard API: %v", config.EnableWebDashboard)
		case "12":
			config.EnableContainerScan = !config.EnableContainerScan
			color.Green("✓ Container Image Scanning: %v", config.EnableContainerScan)
		case "13":
			setAIModel(reader, config)
		case "14":
			setOutputFiles(reader, config)
		case "15":
			configureCompliance(reader, config)
		case "16":
			setOllamaHost(reader, config)
		case "17":
			runDiagnostic()
		case "18":
			if config.TargetDir == "" {
				color.Red("✗ Error: Please set target directory first (Option 1)")
				fmt.Println()
				continue
			}
			config.Save()
			return config
		case "0":
			color.Yellow("Exiting scanner...")
			os.Exit(0)
		default:
			color.Red("✗ Invalid choice. Please enter 0-18.")
		}

		fmt.Println()
		fmt.Print(color.HiBlackString("Press Enter to continue..."))
		reader.ReadString('\n')
	}
}

func showCurrentConfig(config *ScanConfig) {
	fmt.Println(color.HiWhiteString("Current Configuration:"))
	fmt.Printf("  📁 Target Directory:     %s\n", valueOrNotSet(config.TargetDir))
	// AI Mode display
	aiMode := color.HiRedString("✗ Disabled")
	if config.EnableStaticPlusAI {
		aiMode = color.HiGreenString("✓ Static + AI Discovery + Validation")
	} else if config.EnableAIConsolidation {
		aiMode = color.HiGreenString("✓ Consolidated AI + Static Intel (Merge Mode)")
	} else if config.EnableAI && config.EnableAIDiscovery {
		aiMode = color.HiGreenString("✓ AI Discovery (Find + Validate)")
	} else if config.EnableAIDiscovery {
		aiMode = color.HiGreenString("✓ AI Discovery Only")
	} else if config.EnableAI {
		aiMode = color.HiGreenString("✓ AI Validation Only")
	}
	fmt.Printf("  🤖 AI Mode:              %s\n", aiMode)
	fmt.Printf("  🔍 Semgrep Scanning:     %s\n", enabledOrDisabled(config.EnableSemgrep))
	fmt.Printf("  📦 Dependency Scanning:  %s\n", enabledOrDisabled(config.EnableDependencyScan))
	fmt.Printf("  🔑 Secret Detection:     %s\n", enabledOrDisabled(config.EnableSecretDetection))
	fmt.Printf("  🐳 Container Scanning:   %s\n", enabledOrDisabled(config.EnableContainerScan))
	fmt.Printf("  ⛓️  Supply Chain (SBOM):  %s\n", enabledOrDisabled(config.EnableSupplyChain))
	fmt.Printf("  📋 Compliance Checking:  %s\n", enabledOrDisabled(config.EnableCompliance))
	fmt.Printf("  🌐 Threat Intelligence:  %s\n", enabledOrDisabled(config.EnableThreatIntel))
	fmt.Printf("  🔮 Taint/Data Flow:      %s\n", enabledOrDisabled(config.EnableSymbolicExec))
	fmt.Printf("  🧠 ML FP Reduction:      %s\n", enabledOrDisabled(config.EnableMLFPReduction))
	fmt.Printf("  🌐 Web Dashboard API:    %s\n", enabledOrDisabled(config.EnableWebDashboard))
	fmt.Printf("  🧠 AI Model:             %s\n", valueOrNotSet(config.ModelName))
	fmt.Printf("  🌐 Ollama Host:          %s\n", valueOrNotSet(config.OllamaHost))
	fmt.Printf("  📄 Output Files:         %s, %s, %s\n", config.OutputCSV, config.OutputHTML, config.OutputPDF)
	if len(config.ComplianceFrameworks) > 0 {
		fmt.Printf("  📋 Compliance Frameworks: %s\n", strings.Join(config.ComplianceFrameworks, ", "))
	}
}

func valueOrNotSet(value string) string {
	if value == "" {
		return color.HiBlackString("Not set")
	}
	return color.HiGreenString(value)
}

func enabledOrDisabled(enabled bool) string {
	if enabled {
		return color.HiGreenString("✓ Enabled")
	}
	return color.HiRedString("✗ Disabled")
}

func setTargetDirectory(reader *bufio.Reader, config *ScanConfig) {
	fmt.Print("Enter target directory to scan: ")
	dir, _ := reader.ReadString('\n')
	dir = strings.TrimSpace(dir)

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		color.Red("✗ Error: Directory does not exist: %s", dir)
		return
	}

	config.TargetDir = dir
	color.Green("✓ Target directory set to: %s", dir)
}

func setAIModel(reader *bufio.Reader, config *ScanConfig) {
	fmt.Println()
	fmt.Println("Available AI Models:")

	ram, err := utils.GetSystemRAM()
	if err != nil {
		ram = &utils.RAMInfo{AvailableGB: 8.0, TotalGB: 16.0} // Fallback
	}
	models := ai.GetModelRecommendations(ram)

	for i, m := range models {
		status := "✅"
		if !m.FitsRAM {
			status = "⚠️ "
		}
		fmt.Printf("  %d. %s [%s] %s\n", i+1, m.Name, m.RAMRequired, status)
	}
	fmt.Printf("  %d. Custom model name\n", len(models)+1)
	fmt.Println()

	fmt.Printf("Enter choice (1-%d): ", len(models)+1)
	modelChoice, _ := reader.ReadString('\n')
	modelChoice = strings.TrimSpace(modelChoice)

	var choiceInt int
	fmt.Sscanf(modelChoice, "%d", &choiceInt)

	if choiceInt >= 1 && choiceInt <= len(models) {
		config.ModelName = models[choiceInt-1].Name
	} else if choiceInt == len(models)+1 {
		fmt.Print("Enter custom model name: ")
		model, _ := reader.ReadString('\n')
		config.ModelName = strings.TrimSpace(model)
	} else {
		// Default if invalid
		config.ModelName = ai.GetDefaultModel()
	}

	color.Green("✓ AI Model set to: %s", config.ModelName)
}

func setOutputFiles(reader *bufio.Reader, config *ScanConfig) {
	fmt.Print("Enter CSV output file [report.csv]: ")
	csv, _ := reader.ReadString('\n')
	csv = strings.TrimSpace(csv)
	if csv != "" {
		config.OutputCSV = csv
	}

	fmt.Print("Enter HTML output file [report.html]: ")
	html, _ := reader.ReadString('\n')
	html = strings.TrimSpace(html)
	if html != "" {
		config.OutputHTML = html
	}

	fmt.Print("Enter PDF output file [report.pdf]: ")
	pdf, _ := reader.ReadString('\n')
	pdf = strings.TrimSpace(pdf)
	if pdf != "" {
		config.OutputPDF = pdf
	}

	color.Green("✓ Output files configured")
}

func configureCompliance(reader *bufio.Reader, config *ScanConfig) {
	fmt.Println()
	fmt.Println("Select Compliance Frameworks:")
	fmt.Println("  1. PCI-DSS (Payment Card Industry)")
	fmt.Println("  2. HIPAA (Healthcare)")
	fmt.Println("  3. SOC2 (Service Organizations)")
	fmt.Println("  4. ISO27001 (Information Security)")
	fmt.Println("  5. GDPR (Data Privacy)")
	fmt.Println("  6. All of the above")
	fmt.Println("  7. Clear selection")
	fmt.Println()

	fmt.Print("Enter choice (1-7): ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	config.ComplianceFrameworks = []string{}

	switch choice {
	case "1":
		config.ComplianceFrameworks = []string{"PCI-DSS"}
	case "2":
		config.ComplianceFrameworks = []string{"HIPAA"}
	case "3":
		config.ComplianceFrameworks = []string{"SOC2"}
	case "4":
		config.ComplianceFrameworks = []string{"ISO27001"}
	case "5":
		config.ComplianceFrameworks = []string{"GDPR"}
	case "6":
		config.ComplianceFrameworks = []string{"PCI-DSS", "HIPAA", "SOC2", "ISO27001", "GDPR"}
	case "7":
		config.ComplianceFrameworks = []string{}
	}

	if len(config.ComplianceFrameworks) > 0 {
		color.Green("✓ Compliance frameworks: %s", strings.Join(config.ComplianceFrameworks, ", "))
	} else {
		color.Yellow("✓ Compliance checking disabled")
	}
}

func setOllamaHost(reader *bufio.Reader, config *ScanConfig) {
	fmt.Println()
	color.Cyan("🌐 Configure Ollama Host (Remote AI)")
	fmt.Println()
	fmt.Println("  Connect to an Ollama instance on another machine in the same network.")
	fmt.Println("  The remote machine must have Ollama running with OLLAMA_HOST=0.0.0.0")
	fmt.Println()
	fmt.Printf("  Current host: %s\n", color.HiGreenString(config.OllamaHost))
	fmt.Println()
	fmt.Print("  Enter host:port (e.g. 192.168.1.42:11434) or press Enter to keep current: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "" {
		color.Yellow("✓ Keeping current host: %s", config.OllamaHost)
		return
	}

	// Basic validation — must contain a colon for host:port
	if !strings.Contains(input, ":") {
		input = input + ":11434"
		color.Yellow("  ℹ No port specified, using default: %s", input)
	}

	config.OllamaHost = input
	ai.SetOllamaHost(input)
	color.Green("✓ Ollama host set to: %s", input)

	// Test connection
	fmt.Print("  Testing connection... ")
	models := ai.GetInstalledModels()
	if models != nil {
		color.Green("✓ Connected! Found %d model(s)", len(models))
	} else {
		color.Red("✗ Could not connect. Make sure Ollama is running on %s", input)
		color.Yellow("  Tip: On the remote machine, run: OLLAMA_HOST=0.0.0.0 ollama serve")
	}
}

func configureAIMode(reader *bufio.Reader, c *ScanConfig) {
	fmt.Println()
	color.Cyan("🤖 AI Mode Configuration:")
	fmt.Println()
	fmt.Println("  1. AI Validation Only       — Validate findings discovered by the static engine")
	fmt.Println("  2. AI Discovery Only        — Use AI to proactively find new vulnerabilities")
	fmt.Println("  3. AI Discovery + Validate  — Find new issues AND validate all findings")
	fmt.Println("  4. Static + AI + Validate   — Run static rules first, then AI discovery, then validate ALL")
	fmt.Println("  5. Consolidated AI + Static — Run both, stash in DB, and merge using AI")
	fmt.Println("  6. Disable AI               — Turn off all AI features")
	fmt.Println()

	fmt.Print(color.HiYellowString("Enter choice (1-6): "))
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	// Reset all AI flags first
	c.EnableAI = false
	c.EnableAIDiscovery = false
	c.EnableStaticPlusAI = false
	c.EnableAIConsolidation = false

	switch choice {
	case "1":
		c.EnableAI = true
		color.Green("✓ AI Mode: Validation Only")
	case "2":
		c.EnableAIDiscovery = true
		color.Green("✓ AI Mode: Discovery Only")
	case "3":
		c.EnableAI = true
		c.EnableAIDiscovery = true
		color.Green("✓ AI Mode: Discovery + Validation")
	case "4":
		c.EnableAI = true
		c.EnableAIDiscovery = true
		c.EnableStaticPlusAI = true
		color.Green("✓ AI Mode: Static + AI Discovery + Validation")
	case "5":
		c.EnableAIConsolidation = true
		color.Green("✓ AI Mode: Consolidated AI + Static Intel")
	case "6":
		color.Yellow("✓ AI Mode: Disabled")
	default:
		color.Red("✗ Invalid choice. No changes made.")
	}
}

func (c *ScanConfig) LoadRules(rulesDir string) ([]config.Rule, error) {
	return config.LoadRules(rulesDir)
}

func (c *ScanConfig) Save() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}
	configPath := filepath.Join(homeDir, ".scanner-menu-config.json")
	data, err := json.MarshalIndent(c, "", "  ")
	if err == nil {
		os.WriteFile(configPath, data, 0644)
	}
}

func loadSavedConfig() (*ScanConfig, bool) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, false
	}
	configPath := filepath.Join(homeDir, ".scanner-menu-config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, false
	}
	var config ScanConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, false
	}
	// Verify the default model fallback if model was unset
	if config.ModelName == "" {
		config.ModelName = ai.GetDefaultModel()
	}
	return &config, true
}

func runDiagnostic() {
	fmt.Println()
	color.Cyan("🛠️  SYSTEM DIAGNOSTIC")
	fmt.Println("───────────────────────────────────────────────────────")

	// 1. OS Detection
	fmt.Printf("  Operating System (OS): %s\n", color.HiGreenString(runtime.GOOS))
	fmt.Printf("  Architecture (Arch):   %s\n", color.HiGreenString(runtime.GOARCH))

	// 2. RAM Detection
	ram, err := utils.GetSystemRAM()
	if err != nil {
		color.Red("  RAM Detection:     FAILED (%v)", err)
	} else {
		fmt.Printf("  Total RAM:         %.2f GB\n", ram.TotalGB)
		fmt.Printf("  Available RAM:     %.2f GB\n", ram.AvailableGB)
	}

	// 3. External Tools
	fmt.Print("  osv-scanner:       ")
	if scanner.CheckOSVCliInstalled() {
		color.Green("✓ FOUND")
	} else {
		color.Yellow("✗ NOT FOUND (Will use API fallback)")
	}

	fmt.Print("  semgrep:           ")
	// Note: We need getSemgrepBin() which is in semgrep_runner.go (same package scanner)
	// But menu.go is in main package. The runner is exported? No.
	// We'll just check semgrep directly or exported helper.
	_, err = exec.LookPath("semgrep")
	if err == nil {
		color.Green("✓ FOUND")
	} else {
		_, err = exec.LookPath("semgrep.exe")
		if err == nil {
			color.Green("✓ FOUND")
		} else {
			color.Yellow("✗ NOT FOUND (Will skip community rules)")
		}
	}

	// 4. Ollama Connectivity
	fmt.Print("  Ollama Status:     ")
	models := ai.GetInstalledModels()
	if models != nil {
		color.Green("✓ CONNECTED (%d models available)", len(models))
	} else {
		color.Red("✗ DISCONNECTED")
	}

	fmt.Println("───────────────────────────────────────────────────────")
}
