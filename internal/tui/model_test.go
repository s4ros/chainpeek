package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/s4ros/chainpeek/internal/iptables"
	"github.com/s4ros/chainpeek/internal/view"
)

type stubLoader struct{ res iptables.ParseResult }

func (s stubLoader) Load() (iptables.ParseResult, error) { return s.res, nil }

func rules() []iptables.Rule {
	return []iptables.Rule{
		{Table: "filter", Chain: "INPUT", Index: 1, Dport: iptables.Port{Start: 80}, Target: "ACCEPT", Action: iptables.ActionAllow, Raw: "in-80"},
		{Table: "filter", Chain: "INPUT", Index: 2, Dport: iptables.Port{Start: 22}, Target: "ACCEPT", Action: iptables.ActionAllow, Raw: "in-22"},
		{Table: "filter", Chain: "OUTPUT", Index: 1, Dport: iptables.Port{Start: 443}, Target: "ACCEPT", Action: iptables.ActionAllow, Raw: "out-443"},
		{Table: "filter", Chain: "FORWARD", Index: 1, Target: "DROP", Action: iptables.ActionDeny, Raw: "fwd-drop"},
	}
}

func testChains() []string {
	return []string{"INPUT", "OUTPUT", "FORWARD"}
}

func newTestModel() Model {
	r := rules()
	return New(stubLoader{res: iptables.ParseResult{Rules: r, Chains: testChains()}}, r, testChains(), nil)
}

func equalStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func press(m Model, key string) Model {
	next, _ := m.Update(tea.KeyPressMsg{Text: key})
	return next.(Model)
}

func TestArrowMovesCursor(t *testing.T) {
	m := newTestModel()
	if m.Cursor() != 0 {
		t.Fatal(m.Cursor())
	}
	m = press(m, "down")
	if m.Cursor() != 1 {
		t.Fatalf("down -> %d", m.Cursor())
	}
	m = press(m, "up")
	if m.Cursor() != 0 {
		t.Fatalf("up -> %d", m.Cursor())
	}
}

func TestChainFilter(t *testing.T) {
	m := press(newTestModel(), "3")
	if m.Query().Chain != "OUTPUT" {
		t.Fatal(m.Query().Chain)
	}
	if len(m.Visible()) != 1 || m.Visible()[0].Chain != "OUTPUT" {
		t.Fatalf("%+v", m.Visible())
	}
}

func TestActionFilter(t *testing.T) {
	m := press(newTestModel(), "d")
	if m.Query().Action != view.ActionDeny {
		t.Fatal(m.Query().Action)
	}
	if len(m.Visible()) != 1 || m.Visible()[0].Action != iptables.ActionDeny {
		t.Fatal(m.Visible())
	}
}

func TestPortSort(t *testing.T) {
	m := press(newTestModel(), "p")
	if !m.Query().ByPort {
		t.Fatal("expected ByPort")
	}
	if m.Visible()[0].Dport.Start != 22 {
		t.Fatalf("first=%+v", m.Visible()[0])
	}
}

func TestInitialWarningsInView(t *testing.T) {
	r := rules()
	warn := []string{"skipping malformed rule: -A INPUT", "skipping unexpected line: foo"}
	m := sized(New(stubLoader{res: iptables.ParseResult{Rules: r, Chains: testChains()}}, r, testChains(), warn))
	got := m.View().Content
	if !strings.Contains(got, "skipping malformed rule: -A INPUT") {
		t.Fatalf("initial warnings missing from View:\n%s", got)
	}
	if !strings.Contains(got, "skipping unexpected line: foo") {
		t.Fatalf("initial warnings missing from View:\n%s", got)
	}
}

func TestHeaderChainChip(t *testing.T) {
	m := sized(newTestModel())
	got := stripANSI(m.View().Content)
	if !strings.Contains(got, "chain:ALL ▾") {
		t.Fatalf("default chip missing:\n%s", got)
	}
	m = press(m, "2")
	got = stripANSI(m.View().Content)
	if !strings.Contains(got, "chain:INPUT ▾") {
		t.Fatalf("INPUT chip missing:\n%s", got)
	}
}

func TestNewStoresChains(t *testing.T) {
	m := newTestModel()
	if !equalStr(m.chains, testChains()) {
		t.Fatalf("chains=%v", m.chains)
	}
}

func TestQuit(t *testing.T) {
	_, cmd := newTestModel().Update(tea.KeyPressMsg{Text: "q"})
	if cmd == nil {
		t.Fatal("expected tea.Quit")
	}
}

func TestCursorResetsWhenRawGone(t *testing.T) {
	m := newTestModel()
	m = press(m, "down")
	m = press(m, "down")
	m = press(m, "down")
	if m.Cursor() != 3 {
		t.Fatalf("last row -> %d", m.Cursor())
	}
	if m.Visible()[m.Cursor()].Raw != "fwd-drop" {
		t.Fatalf("selected=%+v", m.Visible()[m.Cursor()])
	}
	m = press(m, "a")
	if m.Query().Action != view.ActionAllow {
		t.Fatal(m.Query().Action)
	}
	if m.Cursor() != 0 {
		t.Fatalf("filtered-out raw -> cursor %d want 0", m.Cursor())
	}
}

func TestRuleRowPlainNoANSI(t *testing.T) {
	row := ruleRow(iptables.Rule{
		Index:       1,
		Chain:       "INPUT",
		Protocol:    "tcp",
		Target:      "ACCEPT",
		Action:      iptables.ActionAllow,
		Source:      "10.0.0.0/8",
		Destination: "255.255.255.255/32",
	})
	for _, cell := range row {
		if strings.Contains(cell, "\x1b") {
			t.Fatalf("ruleRow must return plain cells so Selected.Reverse can apply, got %q", row)
		}
	}
	if !cellEq(row, "255.255.255.255/32") {
		t.Fatalf("Destination CIDR missing from ruleRow: %v", row)
	}
}

func TestSelectedRowCellsHaveNoANSI(t *testing.T) {
	m := newTestModel()
	assertPlainRow(t, m.table.SelectedRow(), "cursor 0")
	m = press(m, "down")
	assertPlainRow(t, m.table.SelectedRow(), "cursor 1")
}

func sized(m Model) Model {
	next, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 24})
	return next.(Model)
}

func TestIPv4CIDRNotTruncated(t *testing.T) {
	const cidr = "255.255.255.255/32"
	r := []iptables.Rule{{
		Table: "filter", Chain: "INPUT", Index: 1, Protocol: "tcp",
		Source: cidr, Destination: cidr, Target: "ACCEPT",
		Action: iptables.ActionAllow, Raw: "cidr-row",
	}}
	m := sized(New(stubLoader{res: iptables.ParseResult{Rules: r, Chains: []string{"INPUT"}}}, r, []string{"INPUT"}, nil))
	row := ruleRow(r[0])
	if !cellEq(row, cidr) {
		t.Fatalf("ruleRow missing full CIDR: %v", row)
	}
	cols := m.table.Columns()
	if len(cols) < 7 || cols[5].Width < 18 || cols[6].Width < 18 {
		t.Fatalf("SOURCE/DESTINATION width must be >= 18, got %+v", cols)
	}
	got := stripANSI(m.View().Content)
	if strings.Count(got, cidr) < 2 {
		t.Fatalf("typical IPv4 CIDR truncated in view:\n%s", got)
	}
}

func TestResizeGivesLeftoverToSourceDest(t *testing.T) {
	m := newTestModel()
	base := ruleColumns()
	m = sized(m)
	wide, _ := m.Update(tea.WindowSizeMsg{Width: 200, Height: 24})
	m = wide.(Model)
	cols := m.table.Columns()
	if cols[5].Width <= base[5].Width || cols[6].Width <= base[6].Width {
		t.Fatalf("leftover width should go to SOURCE/DESTINATION, base=%d/%d got=%d/%d",
			base[5].Width, base[6].Width, cols[5].Width, cols[6].Width)
	}
}

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\x1b' {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func TestUnselectedRowsColoredInView(t *testing.T) {
	m := sized(newTestModel())
	deny := rowStyle(iptables.Rule{Action: iptables.ActionDeny}).Render("FORWARD")
	got := m.View().Content
	if !strings.Contains(got, deny) {
		t.Fatalf("unselected DENY row should be red in View, got:\n%s", got)
	}
	allow := rowStyle(iptables.Rule{Action: iptables.ActionAllow}).Render("INPUT")
	if !strings.Contains(got, allow) {
		t.Fatalf("unselected ALLOW row should be green in View, got:\n%s", got)
	}

	only := []iptables.Rule{{
		Table: "filter", Chain: "INPUT", Index: 1, Target: "DROP",
		Action: iptables.ActionDeny, Raw: "only-deny",
	}}
	sel := sized(New(stubLoader{res: iptables.ParseResult{Rules: only, Chains: []string{"INPUT"}}}, only, []string{"INPUT"}, nil))
	red := rowStyle(only[0]).Render("INPUT")
	if strings.Contains(sel.View().Content, red) {
		t.Fatal("selected row must stay unstyled so Reverse applies to the whole line")
	}
}

func cellEq(row []string, want string) bool {
	for _, c := range row {
		if c == want {
			return true
		}
	}
	return false
}

func assertPlainRow(t *testing.T, row []string, label string) {
	t.Helper()
	for _, cell := range row {
		if strings.Contains(cell, "\x1b") {
			t.Fatalf("%s: selected cells must be unstyled, got %q", label, row)
		}
	}
}
