// Package tui is the Bubble Tea interactive table for chainpeek.
package tui

import (
	"strconv"
	"strings"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/table"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/s4ros/chainpeek/internal/iptables"
	"github.com/s4ros/chainpeek/internal/view"
)

const version = "0.1.0-dev"

type Model struct {
	loader      iptables.Loader
	all         []iptables.Rule
	chains      []string
	chainFocus  bool
	chainIndex  int
	chainOffset int
	query       view.Query
	visible     []iptables.Rule
	table       table.Model
	cursorRaw   string
	status      string
	statusErr   bool
	width       int
	height      int
	showHelp    bool
}

func New(loader iptables.Loader, rules []iptables.Rule, chains []string, warnings []string) Model {
	m := Model{
		loader: loader,
		all:    append([]iptables.Rule(nil), rules...),
		chains: append([]string(nil), chains...),
	}
	if len(warnings) > 0 {
		m.status = strings.Join(warnings, "; ")
	}
	m.table = table.New(
		table.WithColumns(ruleColumns()),
		table.WithFocused(true),
		table.WithHeight(20),
		table.WithKeyMap(navKeyMap()),
		table.WithStyles(tableStyles()),
	)
	m.recompute()
	return m
}

func (m Model) Init() tea.Cmd { return nil }

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		return m.handleKey(msg.String())
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.resize()
		return m, nil
	}
	return m, nil
}

func (m Model) Cursor() int { return m.table.Cursor() }

func (m Model) Visible() []iptables.Rule { return m.visible }

func (m Model) Query() view.Query { return m.query }

func (m *Model) recompute() {
	m.visible = view.Apply(m.all, m.query)
	rows := make([]table.Row, 0, len(m.visible))
	restore := -1
	for i, r := range m.visible {
		rows = append(rows, ruleRow(r))
		if m.cursorRaw != "" && r.Raw == m.cursorRaw {
			restore = i
		}
	}
	m.table.SetRows(rows)
	if len(rows) == 0 {
		m.cursorRaw = ""
		return
	}
	if restore < 0 {
		restore = 0
	}
	m.table.SetCursor(restore)
	m.cursorRaw = m.visible[m.table.Cursor()].Raw
}

func (m *Model) syncCursorRaw() {
	i := m.table.Cursor()
	if i >= 0 && i < len(m.visible) {
		m.cursorRaw = m.visible[i].Raw
	}
}

func (m *Model) reload() {
	if m.loader == nil {
		m.status = "no loader"
		m.statusErr = true
		return
	}
	res, err := m.loader.Load()
	if err != nil {
		m.status = err.Error()
		m.statusErr = true
		return
	}
	m.all = append([]iptables.Rule(nil), res.Rules...)
	m.chains = append([]string(nil), res.Chains...)
	m.statusErr = false
	prev := m.query.Chain
	gone := false
	if prev != "" {
		found := false
		for _, c := range m.chains {
			if c == prev {
				found = true
				break
			}
		}
		if !found {
			m.query.Chain = ""
			m.status = "chain " + prev + " gone, showing ALL"
			gone = true
		}
	}
	if gone {
		if len(res.Warnings) > 0 {
			m.status += "; " + strings.Join(res.Warnings, "; ")
		}
	} else if len(res.Warnings) > 0 {
		m.status = strings.Join(res.Warnings, "; ")
	} else {
		m.status = "reloaded"
	}
	m.syncChainIndex()
	m.recompute()
	m.resize()
}

func (m *Model) resize() {
	if m.width > 0 {
		m.table.SetWidth(m.width)
		m.table.SetColumns(columnsForWidth(m.width))
	}
	if m.height > 0 {
		h := m.height - 4
		if m.chainFocus && !m.showHelp {
			h -= m.overlayHeight()
		}
		if h < 3 {
			h = 3
		}
		m.table.SetHeight(h)
	}
	if m.chainFocus && !m.showHelp {
		m.ensureChainVisible()
	}
}

func (m Model) overlayItems() []string {
	items := make([]string, 0, 1+len(m.chains))
	items = append(items, "")
	items = append(items, m.chains...)
	return items
}

func (m *Model) syncChainIndex() {
	if m.query.Chain == "" {
		m.chainIndex = 0
		return
	}
	for i, name := range m.chains {
		if name == m.query.Chain {
			m.chainIndex = i + 1
			return
		}
	}
	m.chainIndex = -1
}

func (m *Model) setChain(name string) {
	m.query.Chain = name
	m.syncChainIndex()
	m.ensureChainVisible()
	m.recompute()
}

func (m *Model) overlayHeight() int {
	n := 1 + len(m.chains)
	if m.height <= 0 {
		return n
	}
	capH := m.height - 7 // header, footer, 3 table rows
	if capH < 1 {
		capH = 1
	}
	if n < capH {
		return n
	}
	return capH
}

func (m *Model) ensureChainVisible() {
	h := m.overlayHeight()
	if m.chainIndex < 0 {
		return
	}
	if m.chainIndex < m.chainOffset {
		m.chainOffset = m.chainIndex
	}
	if m.chainIndex >= m.chainOffset+h {
		m.chainOffset = m.chainIndex - h + 1
	}
	if m.chainOffset < 0 {
		m.chainOffset = 0
	}
}

func (m *Model) moveChain(delta int) {
	items := m.overlayItems()
	n := len(items)
	if n == 0 {
		return
	}
	i := m.chainIndex
	if i < 0 {
		if delta > 0 {
			i = 0
		} else {
			i = n - 1
		}
	} else {
		i += delta
	}
	if i < 0 {
		i = 0
	}
	if i >= n {
		i = n - 1
	}
	m.chainIndex = i
	m.query.Chain = items[i]
	m.ensureChainVisible()
	m.recompute()
}

func (m *Model) jumpChain(i int) {
	items := m.overlayItems()
	n := len(items)
	if n == 0 {
		return
	}
	if i < 0 {
		i = 0
	}
	if i >= n {
		i = n - 1
	}
	m.chainIndex = i
	m.query.Chain = items[i]
	m.ensureChainVisible()
	m.recompute()
}

func overlayLabel(name string) string {
	if name == "" {
		return "ALL"
	}
	return name
}

func (m Model) chainOverlayView() string {
	items := m.overlayItems()
	h := m.overlayHeight()
	start := m.chainOffset
	if start < 0 {
		start = 0
	}
	if start > len(items) {
		start = len(items)
	}
	end := start + h
	if end > len(items) {
		end = len(items)
	}
	var b strings.Builder
	for i := start; i < end; i++ {
		prefix := "  "
		if i == m.chainIndex {
			prefix = "▸ "
		}
		b.WriteString(prefix)
		b.WriteString(overlayLabel(items[i]))
		if i+1 < end {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

const minCIDRWidth = 18

func ruleColumns() []table.Column {
	return []table.Column{
		{Title: "#", Width: 4},
		{Title: "CHAIN", Width: 12},
		{Title: "PROTO", Width: 6},
		{Title: "DPORT", Width: 10},
		{Title: "SPORT", Width: 10},
		{Title: "SOURCE", Width: minCIDRWidth},
		{Title: "DESTINATION", Width: minCIDRWidth},
		{Title: "TARGET", Width: 12},
	}
}

func columnsForWidth(width int) []table.Column {
	cols := ruleColumns()
	if width <= 0 {
		return cols
	}
	used := 2 * len(cols) // Cell Padding(0, 1)
	for _, c := range cols {
		used += c.Width
	}
	leftover := width - used
	if leftover < 2 {
		return cols
	}
	left := leftover / 2
	cols[5].Width += left
	cols[6].Width += leftover - left
	return cols
}

func navKeyMap() table.KeyMap {
	return table.KeyMap{
		LineUp: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("↑/k", "up"),
		),
		LineDown: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("↓/j", "down"),
		),
		PageUp: key.NewBinding(
			key.WithKeys("pgup"),
			key.WithHelp("pgup", "page up"),
		),
		PageDown: key.NewBinding(
			key.WithKeys("pgdown"),
			key.WithHelp("pgdn", "page down"),
		),
		HalfPageUp: key.NewBinding(
			key.WithKeys("ctrl+u"),
			key.WithHelp("ctrl+u", "½ page up"),
		),
		HalfPageDown: key.NewBinding(
			key.WithKeys("ctrl+d"),
			key.WithHelp("ctrl+d", "½ page down"),
		),
		GotoTop: key.NewBinding(
			key.WithKeys("home", "g"),
			key.WithHelp("g/home", "go to start"),
		),
		GotoBottom: key.NewBinding(
			key.WithKeys("end", "G"),
			key.WithHelp("G/end", "go to end"),
		),
	}
}

func tableStyles() table.Styles {
	s := table.DefaultStyles()
	s.Header = lipgloss.NewStyle().Bold(true).Padding(0, 1)
	s.Cell = lipgloss.NewStyle().Padding(0, 1)
	// Reverse wraps the joined row. Cells must stay unstyled so a per-cell
	// reset cannot clear reverse for the rest of the selection.
	s.Selected = lipgloss.NewStyle().Reverse(true).Bold(true)
	return s
}

// ruleRow returns plain cell text. bubbles/v2 table.Styles has no per-row
// function; action colors are applied to unselected rows in coloredTableView.
func ruleRow(r iptables.Rule) table.Row {
	return table.Row{
		strconv.Itoa(r.Index),
		dash(r.Chain),
		dash(r.Protocol),
		formatPort(r.Dport),
		formatPort(r.Sport),
		dash(r.Source),
		dash(r.Destination),
		dash(r.Target),
	}
}

func rowStyle(r iptables.Rule) lipgloss.Style {
	switch r.Action {
	case iptables.ActionAllow:
		return lipgloss.NewStyle().Foreground(lipgloss.Green)
	case iptables.ActionDeny:
		return lipgloss.NewStyle().Foreground(lipgloss.Red)
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Yellow)
	}
}

func formatPort(p iptables.Port) string {
	if p.Start == 0 {
		return "-"
	}
	if p.End > 0 && p.End != p.Start {
		return strconv.Itoa(p.Start) + ":" + strconv.Itoa(p.End)
	}
	return strconv.Itoa(p.Start)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
