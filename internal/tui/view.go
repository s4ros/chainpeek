package tui

import (
	"strings"

	"charm.land/bubbles/v2/table"
	tea "charm.land/bubbletea/v2"

	"github.com/s4ros/chainpeek/internal/view"
)

const keymapLine = "↑/↓ move  ·  c/tab chain  ·  1 all  2 IN  3 OUT  4 FWD  ·  a ACCEPT  d DENY  f all  ·  p port  r reload  ·  ? help  q quit"

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
	w := m.frameWidth()
	inner := m.innerWidth()

	var b strings.Builder
	b.WriteString(topBar(w, m.titleLeft(), m.titleRight()))
	b.WriteByte('\n')
	b.WriteString(boxLines(padLeft(m.chipsLine()), inner))

	if m.showHelp {
		b.WriteByte('\n')
		b.WriteString(sectionRule(w, ""))
		b.WriteByte('\n')
		b.WriteString(boxLines(padLeft(helpText), inner))
	} else {
		if m.chainFocus {
			b.WriteByte('\n')
			b.WriteString(sectionRule(w, "chain"))
			b.WriteByte('\n')
			b.WriteString(boxLines(m.chainOverlayView(inner), inner))
			b.WriteByte('\n')
			b.WriteString(sectionRule(w, "rules"))
		} else {
			b.WriteByte('\n')
			b.WriteString(sectionRule(w, ""))
		}
		if len(m.visible) == 0 {
			b.WriteByte('\n')
			b.WriteString(boxLines(padLeft(emptyStyle.Render("no rules match filters")), inner))
		}
		b.WriteByte('\n')
		b.WriteString(boxLines(m.coloredTableView(), inner))
	}
	b.WriteByte('\n')
	b.WriteString(bottomBar(w))

	content := b.String() + "\n" + m.footer()
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

func (m Model) footer() string {
	keys := keyStyle.Render(keymapLine)
	if m.status == "" {
		return keys
	}
	status := m.status
	switch {
	case m.statusErr:
		status = errStyle.Render(status)
	case m.status == "reloaded":
		status = okStyle.Render(status)
	default:
		status = warnStyle.Render(status)
	}
	return status + "\n" + keys
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
