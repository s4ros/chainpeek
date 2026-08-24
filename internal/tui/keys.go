package tui

import (
	tea "charm.land/bubbletea/v2"

	"github.com/s4ros/chainpeek/internal/view"
)

func (m Model) handleKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "c":
		m.chainFocus = true
		m.resize()
		return m, nil
	case "tab", "\t":
		m.chainFocus = !m.chainFocus
		m.resize()
		return m, nil
	case "enter", "esc":
		if m.chainFocus {
			m.chainFocus = false
			m.resize()
			return m, nil
		}
	case "1":
		m.setChain("")
	case "2":
		m.setChain("INPUT")
	case "3":
		m.setChain("OUTPUT")
	case "4":
		m.setChain("FORWARD")
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
		m.resize()
	case "q", "ctrl+c":
		return m, tea.Quit
	case "up", "k":
		if m.chainFocus {
			m.moveChain(-1)
			return m, nil
		}
		return m.moveTable(key)
	case "down", "j":
		if m.chainFocus {
			m.moveChain(1)
			return m, nil
		}
		return m.moveTable(key)
	case "pgup":
		if m.chainFocus {
			m.moveChain(-m.overlayHeight())
			return m, nil
		}
		return m.moveTable(key)
	case "pgdown":
		if m.chainFocus {
			m.moveChain(m.overlayHeight())
			return m, nil
		}
		return m.moveTable(key)
	case "home", "g":
		if m.chainFocus {
			m.jumpChain(0)
			return m, nil
		}
		return m.moveTable(key)
	case "end", "G":
		if m.chainFocus {
			m.jumpChain(len(m.overlayItems()) - 1)
			return m, nil
		}
		return m.moveTable(key)
	}
	return m, nil
}

func (m Model) moveTable(key string) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.table, cmd = m.table.Update(tea.KeyPressMsg{Text: key})
	m.syncCursorRaw()
	return m, cmd
}
