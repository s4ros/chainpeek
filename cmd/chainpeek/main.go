package main

import (
	"fmt"
	"os"
)

const version = "0.1.0-dev"

const usage = `chainpeek — interactive TUI for iptables rules

Usage:
  chainpeek [flags]

Flags:
  --file PATH   Read rules from an iptables-save dump instead of the live system
  -h, --help    Show this help
  -v, --version Show version

Keyboard (planned):
  ↑/k  ↓/j     Move selection
  1            All chains
  2/3/4        INPUT / OUTPUT / FORWARD
  a / d / f    ALLOW / DENY / all actions
  p            Sort by port
  r            Refresh
  q            Quit
`

func main() {
	for _, arg := range os.Args[1:] {
		switch arg {
		case "-h", "--help":
			fmt.Print(usage)
			return
		case "-v", "--version":
			fmt.Println("chainpeek", version)
			return
		}
	}

	fmt.Fprintln(os.Stderr, "chainpeek: TUI not implemented yet — see docs/superpowers/plans/")
	os.Exit(2)
}
