package tui

import (
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

func newTestModel() Model {
	r := rules()
	return New(stubLoader{res: iptables.ParseResult{Rules: r}}, r)
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
	if m.Query().Chain != view.ChainOutput {
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
