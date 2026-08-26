package tui

import (
	"fmt"
	"strings"

	"charm.land/bubbles/v2/table"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/s4ros/chainpeek/internal/view"
)

const keymapLine = "↑/↓ move  c/tab chain  1 all  2 IN  3 OUT  4 FWD  a ACCEPT  d DENY  f all  p port  r reload  ? help  q quit"

const helpText = `Keys:
  ↑/k  ↓/j     Move selection (table, or chain list when focused)
  pgup/pgdn    Page
  g/home       First row
  G/end        Last row
  c            Focus chain dropdown
  tab          Toggle chain dropdown
  enter/esc    Leave chain dropdown (keeps current chain)
  1            All chains
  2/3/4        INPUT / OUTPUT / FORWARD
  a / d / f    ACCEPT / DENY / all actions
  p            Toggle sort by port
  r            Reload
  ?            Toggle this help
  q / ctrl+c   Quit`

func (m Model) View() tea.View {
	var body string
	if m.showHelp {
		body = helpText
	} else {
		if m.chainFocus {
			body = m.chainOverlayView() + "\n"
		}
		tableView := m.coloredTableView()
		if len(m.visible) == 0 {
			tableView = "no rules match filters\n" + tableView
		}
		body += tableView
	}
	content := strings.Join([]string{m.header(), body, m.footer()}, "\n")
	v := tea.NewView(content)
	v.AltScreen = true
	return v
}

// coloredTableView paints ACCEPT/DENY/OTHER on unselected rows only. The
// selected row stays plain so table.Styles.Selected Reverse applies to the
// whole line. bubbles/v2 table.SetStyles takes a Styles struct, not a function.
func (m Model) coloredTableView() string {
	cur := m.table.Cursor()
	rows := make([]table.Row, len(m.visible))
	for i, r := range m.visible {
		row := ruleRow(r)
		if i != cur {
			style := rowStyle(r)
			for j, c := range row {
				row[j] = style.Render(c)
			}
		}
		rows[i] = row
	}
	m.table.SetRows(rows)
	return m.table.View()
}

func (m Model) header() string {
	chip := fmt.Sprintf("chain:%s ▾", chainLabel(m.query.Chain))
	if m.chainFocus {
		chip = lipgloss.NewStyle().Reverse(true).Bold(true).Render(chip)
	}
	return fmt.Sprintf(
		"chainpeek v%s    %d/%d rules    %s    action:%s    sort:%s",
		version,
		len(m.visible),
		len(m.all),
		chip,
		actionLabel(m.query.Action),
		sortLabel(m.query.ByPort),
	)
}

func (m Model) footer() string {
	if m.status == "" {
		return keymapLine
	}
	status := m.status
	if m.statusErr {
		status = lipgloss.NewStyle().Foreground(lipgloss.Red).Render(status)
	}
	return status + "\n" + keymapLine
}

func chainLabel(c string) string {
	if c == "" {
		return "ALL"
	}
	return c
}

func actionLabel(a view.ActionFilter) string {
	switch a {
	case view.ActionAllow:
		return "ACCEPT"
	case view.ActionDeny:
		return "DENY"
	default:
		return "ALL"
	}
}

func sortLabel(byPort bool) string {
	if byPort {
		return "PORT"
	}
	return "CHAIN"
}
