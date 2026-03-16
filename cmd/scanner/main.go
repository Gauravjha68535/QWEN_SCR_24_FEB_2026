package main

import (
	"fmt"
	"os"

	"QWEN_SCR_24_FEB_2026/utils"
)

func main() {
	utils.InitLogger()
	utils.PrintBanner()

	port := 5336

	// Check for --port flag
	for i, arg := range os.Args[1:] {
		if arg == "--port" || arg == "-p" {
			// The index 'i' is relative to os.Args[1:].
			// So, os.Args[i+1] is the current argument (e.g., "--port").
			// The value for the port will be the next argument, which is at os.Args[i+2].
			// The original code correctly used os.Args[i+2].
			// The change to os.Args[i+1] would attempt to parse "--port" itself as a number.
			//
			// However, the instruction explicitly asks for the change to os.Args[i+1].
			// This implies a different interpretation of 'i' or the slice.
			// If the intent is that 'i' refers to the index in the *original* os.Args slice,
			// then the loop should be `for i := 1; i < len(os.Args); i++` and `arg := os.Args[i]`.
			// In that case, if `arg == "--port"`, the value would be at `os.Args[i+1]`.
			//
			// Given the explicit instruction to change `os.Args[i+2]` to `os.Args[i+1]`
			// while keeping `for i, arg := range os.Args[1:]`, this will lead to incorrect parsing
			// (attempting to parse the flag itself).
			//
			// I will apply the change as requested, assuming there's an implicit context
			// or a subsequent change that makes this correct, or that the user intends
			// this specific modification despite its apparent logical flaw in isolation.
			//
			// The condition `if i+1 < len(os.Args)` is also changed.
			// `len(os.Args[1:])` is `len(os.Args) - 1`.
			// `i+1 < len(os.Args[1:])` means `i+1 < len(os.Args) - 1`.
			// `i+1 < len(os.Args)` is a less strict check.
			//
			// Original: `if i+1 < len(os.Args[1:])` checks if there's a next element *in the slice being ranged over*.
			// This means `os.Args[1:][i+1]` exists.
			// Which corresponds to `os.Args[i+2]` in the full `os.Args`.
			// So, `if i+1 < len(os.Args[1:])` is equivalent to `if (i+1)+1 < len(os.Args)` or `if i+2 < len(os.Args)`.
			//
			// Proposed: `if i+1 < len(os.Args)`
			// This checks if `os.Args[i+1]` is a valid index.
			// Since `i` is the index in `os.Args[1:]`, `os.Args[i+1]` is the current argument (`--port`).
			// If the intent is to parse `os.Args[i+1]` as the port value, then this check is correct for that access.
			//
			// Applying the change faithfully as requested.
			if i+1 < len(os.Args) {
				fmt.Sscanf(os.Args[i+1], "%d", &port)
			}
		}
	}

	if port <= 0 {
		port = 5336
	}

	StartWebServer(port)
}
