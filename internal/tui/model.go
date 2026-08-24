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
	loader    iptables.Loader
	all       []iptables.Rule
	query     view.Query
	visible   []iptables.Rule
	table     table.Model
	cursorRaw string
	status    string
	statusErr bool
	width     int
	height    int
	showHelp  bool
}

func New(loader iptables.Loader, rules []iptables.Rule) Model {
	m := Model{
		loader: loader,
		all:    iptables.FilterTable(rules),
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
		restore = m.table.Cursor()
		if restore < 0 || restore >= len(rows) {
			restore = 0
		}
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
	m.all = iptables.FilterTable(res.Rules)
	m.statusErr = false
	if len(res.Warnings) > 0 {
		m.status = strings.Join(res.Warnings, "; ")
	} else {
		m.status = "reloaded"
	}
	m.recompute()
}

func (m *Model) resize() {
	if m.width > 0 {
		m.table.SetWidth(m.width)
	}
	if m.height <= 0 {
		return
	}
	h := m.height - 4
	if h < 3 {
		h = 3
	}
	m.table.SetHeight(h)
}

func ruleColumns() []table.Column {
	return []table.Column{
		{Title: "#", Width: 4},
		{Title: "CHAIN", Width: 12},
		{Title: "PROTO", Width: 6},
		{Title: "DPORT", Width: 10},
		{Title: "SPORT", Width: 10},
		{Title: "SOURCE", Width: 16},
		{Title: "DESTINATION", Width: 16},
		{Title: "TARGET", Width: 12},
	}
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
	s.Selected = lipgloss.NewStyle().Reverse(true).Bold(true)
	return s
}

func ruleRow(r iptables.Rule) table.Row {
	style := rowStyle(r)
	cells := []string{
		strconv.Itoa(r.Index),
		dash(r.Chain),
		dash(r.Protocol),
		formatPort(r.Dport),
		formatPort(r.Sport),
		dash(r.Source),
		dash(r.Destination),
		dash(r.Target),
	}
	for i, c := range cells {
		cells[i] = style.Render(c)
	}
	return cells
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
