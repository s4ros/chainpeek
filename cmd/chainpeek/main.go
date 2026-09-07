package main

import (
	"fmt"
	"os"

	tea "charm.land/bubbletea/v2"

	"github.com/s4ros/chainpeek/internal/iptables"
	"github.com/s4ros/chainpeek/internal/tui"
)

const version = "1.0.1"

const usage = `chainpeek — interactive TUI for iptables rules

Usage:
  chainpeek [--file PATH] [-h|--help] [-v|--version]

Flags:
  --file PATH   Read rules from an iptables-save dump instead of the live system
  -h, --help    Show this help
  -v, --version Show version

Keyboard:
  ↑/k  ↓/j     Move selection
  c / tab      Focus / toggle chain dropdown
  1            All chains
  2/3/4        INPUT / OUTPUT / FORWARD
  a / d / f    ACCEPT / DENY / all actions
  p            Sort by port
  r            Reload
  ?            Help
  q            Quit
`

type options struct {
	help    bool
	version bool
	file    string
}

func parseArgs(args []string) (options, error) {
	var o options
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-h", "--help":
			o.help = true
		case "-v", "--version":
			o.version = true
		case "--file":
			if i+1 >= len(args) {
				return o, fmt.Errorf("chainpeek: --file requires a path")
			}
			i++
			o.file = args[i]
		default:
			return o, fmt.Errorf("chainpeek: unknown flag %s", args[i])
		}
	}
	return o, nil
}

func main() {
	o, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if o.help {
		fmt.Print(usage)
		return
	}
	if o.version {
		fmt.Println("chainpeek", version)
		return
	}

	var loader iptables.Loader
	if o.file != "" {
		loader = iptables.FileLoader{Path: o.file}
	} else {
		loader = iptables.DefaultCmdLoader()
	}

	res, err := loader.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	m := tui.New(loader, res)
	if _, err := tea.NewProgram(m).Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
