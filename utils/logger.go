package utils

import (
	"fmt"

	"github.com/fatih/color"
)

var InfoColor = color.New(color.FgGreen, color.Bold)
var ErrorColor = color.New(color.FgRed, color.Bold)
var WarnColor = color.New(color.FgYellow, color.Bold)

func LogInfo(msg string) {
	InfoColor.Print("[✓] ")
	fmt.Println(msg)
}

func LogError(msg string, err error) {
	ErrorColor.Print("[✗] ")
	fmt.Printf("%s: %v\n", msg, err)
}

func LogWarn(msg string) {
	WarnColor.Print("[⚠] ")
	fmt.Println(msg)
}

func PrintBanner() {
	fmt.Println()
	color.Set(color.FgMagenta)
	fmt.Print(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   🔒  SENTRYQ: AI-POWERED SECURITY SCANNER               ║
║                                                           ║
║   Version 2.0 | Built with Go + Ollama AI                ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
`)
	color.Unset()
}
