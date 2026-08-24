package tui

import (
	tea "charm.land/bubbletea/v2"

	"github.com/s4ros/chainpeek/internal/view"
)

func (m Model) handleKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "1":
		m.query.Chain = view.ChainAll
		m.recompute()
	case "2":
		m.query.Chain = view.ChainInput
		m.recompute()
	case "3":
		m.query.Chain = view.ChainOutput
		m.recompute()
	case "4":
		m.query.Chain = view.ChainForward
		m.recompute()
	case "a":
		m.query.Action = view.ActionAllow
		m.recompute()
	case "d":
		m.query.Action = view.ActionDeny
		m.recompute()
	case "f":
		m.query.Action = view.ActionAll
		m.recompute()
	case "p":
		m.query.ByPort = !m.query.ByPort
		m.recompute()
	case "r":
		m.reload()
	case "?":
		m.showHelp = !m.showHelp
	case "q", "ctrl+c":
		return m, tea.Quit
	case "up", "down", "pgup", "pgdown", "home", "end", "k", "j", "g", "G":
		var cmd tea.Cmd
		m.table, cmd = m.table.Update(tea.KeyPressMsg{Text: key})
		m.syncCursorRaw()
		return m, cmd
	}
	return m, nil
}
