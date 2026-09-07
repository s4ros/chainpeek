package tui

import (
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

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

func TestActionLabelsMatchIptablesSave(t *testing.T) {
	m := sized(newTestModel())
	got := stripANSI(m.View().Content)
	if strings.Contains(got, "ALLOW") {
		t.Fatalf("TUI must use ACCEPT, not ALLOW:\n%s", got)
	}
	if !strings.Contains(got, "a ACCEPT") {
		t.Fatalf("keymap should say a ACCEPT:\n%s", got)
	}
	if !strings.Contains(got, "d DENY") {
		t.Fatalf("keymap should say d DENY:\n%s", got)
	}

	m = press(m, "a")
	got = stripANSI(m.View().Content)
	if !strings.Contains(got, "action:ACCEPT") {
		t.Fatalf("a should show action:ACCEPT:\n%s", got)
	}

	m = press(m, "d")
	got = stripANSI(m.View().Content)
	if !strings.Contains(got, "action:DENY") {
		t.Fatalf("d should show action:DENY:\n%s", got)
	}

	m = press(m, "?")
	got = stripANSI(m.View().Content)
	if strings.Contains(got, "ALLOW") {
		t.Fatalf("help must use ACCEPT, not ALLOW:\n%s", got)
	}
	if !strings.Contains(got, "ACCEPT / DENY") {
		t.Fatalf("help should say ACCEPT / DENY:\n%s", got)
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

func TestFrameChrome(t *testing.T) {
	m := sized(newTestModel())
	raw := m.View().Content
	got := stripANSI(raw)
	for _, tok := range []string{"╭", "╰", "│", "chainpeek", "4/4 rules", "chain:ALL ▾", "action:ALL", "sort:CHAIN"} {
		if !strings.Contains(got, tok) {
			t.Fatalf("%q missing from framed view:\n%s", tok, got)
		}
	}
	if strings.Contains(got, "├─ chain") {
		t.Fatalf("chain section should be hidden until overlay focus:\n%s", got)
	}
	for _, line := range strings.Split(strings.TrimRight(raw, "\n"), "\n") {
		plain := stripANSI(line)
		if plain == "" {
			continue
		}
		r := []rune(plain)[0]
		switch r {
		case '╭', '╰', '│', '├':
			if n := lipgloss.Width(line); n != 120 {
				t.Fatalf("frame line width %d want 120: %q", n, plain)
			}
		}
	}
}

func TestOverlaySectionTitle(t *testing.T) {
	m := sized(press(newTestModel(), "c"))
	got := stripANSI(m.View().Content)
	if !strings.Contains(got, "├─ chain") {
		t.Fatalf("focused overlay should have titled separator:\n%s", got)
	}
	if !strings.Contains(got, "▸ ALL") {
		t.Fatalf("overlay cursor missing:\n%s", got)
	}
}

func TestHelpFramed(t *testing.T) {
	m := sized(press(newTestModel(), "?"))
	got := stripANSI(m.View().Content)
	if !strings.Contains(got, "help") {
		t.Fatalf("help title missing:\n%s", got)
	}
	if !strings.Contains(got, "╭") || !strings.Contains(got, "Focus chain dropdown") {
		t.Fatalf("help should stay inside the frame:\n%s", got)
	}
	if strings.Contains(got, "├─ chain") {
		t.Fatalf("help should hide overlay section:\n%s", got)
	}
}

func TestNewStoresChains(t *testing.T) {
	m := newTestModel()
	if !equalStr(m.chains, testChains()) {
		t.Fatalf("chains=%v", m.chains)
	}
}

func TestOverlayListsDumpChains(t *testing.T) {
	r := rules()
	chains := []string{"INPUT", "FORWARD", "OUTPUT", "DOCKER", "DOCKER-USER", "PREROUTING"}
	m := sized(New(stubLoader{}, r, chains, nil))
	m = press(m, "c")
	got := stripANSI(m.View().Content)
	for _, name := range []string{"DOCKER", "DOCKER-USER", "PREROUTING"} {
		if !strings.Contains(got, name) {
			t.Fatalf("%s missing from overlay:\n%s", name, got)
		}
	}
}

func TestSelectDumpChainShowsNatRules(t *testing.T) {
	r := []iptables.Rule{
		{Table: "filter", Chain: "INPUT", Index: 1, Target: "ACCEPT", Action: iptables.ActionAllow, Raw: "in"},
		{Table: "nat", Chain: "DOCKER", Index: 1, Target: "DNAT", Action: iptables.ActionOther, Raw: "docker-dnat"},
	}
	m := New(stubLoader{}, r, []string{"INPUT", "DOCKER"}, nil)
	m.setChain("DOCKER")
	if len(m.Visible()) != 1 || m.Visible()[0].Raw != "docker-dnat" {
		t.Fatalf("DOCKER from iptables-save should show nat rules, got %+v", m.Visible())
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
		t.Fatalf("unselected ACCEPT row should be green in View, got:\n%s", got)
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

func TestChainOverlayFocus(t *testing.T) {
	m := sized(newTestModel())
	if strings.Contains(stripANSI(m.View().Content), "▸ ALL") {
		t.Fatal("overlay visible before focus")
	}
	m = press(m, "c")
	if !m.chainFocus {
		t.Fatal("c should focus overlay")
	}
	got := stripANSI(m.View().Content)
	if !strings.Contains(got, "▸ ALL") {
		t.Fatalf("overlay missing ALL:\n%s", got)
	}
	if !strings.Contains(got, "INPUT") || !strings.Contains(got, "FORWARD") {
		t.Fatalf("overlay missing chains:\n%s", got)
	}
	m = press(m, "c")
	if !m.chainFocus {
		t.Fatal("c while focused is a no-op")
	}
}

func TestChainOverlayTabToggles(t *testing.T) {
	m := sized(press(newTestModel(), "tab"))
	if !m.chainFocus {
		t.Fatal("tab should focus")
	}
	m = press(m, "tab")
	if m.chainFocus {
		t.Fatal("tab should unfocus")
	}
}

func TestChainOverlayLiveFilter(t *testing.T) {
	m := press(newTestModel(), "c")
	m = press(m, "down")
	if m.Query().Chain != "INPUT" {
		t.Fatalf("live chain=%q", m.Query().Chain)
	}
	for _, r := range m.Visible() {
		if r.Chain != "INPUT" {
			t.Fatalf("visible %+v", r)
		}
	}
	m = press(m, "esc")
	if m.chainFocus {
		t.Fatal("esc should unfocus")
	}
	if m.Query().Chain != "INPUT" {
		t.Fatal("esc must not revert chain")
	}
	m = press(m, "c")
	m = press(m, "enter")
	if m.chainFocus {
		t.Fatal("enter should unfocus")
	}
	if m.Query().Chain != "INPUT" {
		t.Fatal("enter must not revert chain")
	}
}

func TestChainShortcutsStay(t *testing.T) {
	m := press(newTestModel(), "3")
	if m.Query().Chain != "OUTPUT" {
		t.Fatal(m.Query().Chain)
	}
	m = press(m, "c")
	m = press(m, "1")
	if m.Query().Chain != "" {
		t.Fatal(m.Query().Chain)
	}
	if m.chainIndex != 0 {
		t.Fatalf("ALL index=%d", m.chainIndex)
	}
}

func TestEmptyFilterMessage(t *testing.T) {
	m := sized(press(newTestModel(), "2"))
	m = press(m, "d")
	got := stripANSI(m.View().Content)
	if !strings.Contains(got, "no rules match filters") {
		t.Fatalf("empty filter should explain itself:\n%s", got)
	}
	if !strings.Contains(got, "╭") {
		t.Fatalf("empty state should stay framed:\n%s", got)
	}
}

func TestMissingBuiltinHasNoOverlayCursor(t *testing.T) {
	r := []iptables.Rule{{
		Table: "filter", Chain: "CUSTOM", Index: 1, Target: "ACCEPT",
		Action: iptables.ActionAllow, Raw: "custom",
	}}
	m := New(stubLoader{res: iptables.ParseResult{Rules: r, Chains: []string{"CUSTOM"}}}, r, []string{"CUSTOM"}, nil)
	m = press(m, "2")
	if m.Query().Chain != "INPUT" {
		t.Fatal(m.Query().Chain)
	}
	if m.chainIndex != -1 {
		t.Fatalf("expected no ▸, index=%d", m.chainIndex)
	}
	if len(m.Visible()) != 0 {
		t.Fatalf("expected empty table, got %+v", m.Visible())
	}
}

func TestHelpHidesOverlayKeepsFocus(t *testing.T) {
	m := sized(press(newTestModel(), "c"))
	m = press(m, "?")
	got := stripANSI(m.View().Content)
	if !m.chainFocus {
		t.Fatal("help should not clear chainFocus")
	}
	if strings.Contains(got, "▸ ALL") {
		t.Fatal("help should hide overlay")
	}
	if !strings.Contains(got, "Focus chain dropdown") {
		t.Fatalf("help should document chain dropdown:\n%s", got)
	}
	m = press(m, "?")
	if !strings.Contains(stripANSI(m.View().Content), "▸ ALL") {
		t.Fatal("closing help should restore overlay")
	}
}

func TestReloadDropsMissingChain(t *testing.T) {
	r := rules()
	loader := &stubLoader{res: iptables.ParseResult{
		Rules:  r,
		Chains: []string{"INPUT", "OUTPUT", "FORWARD", "DOCKER"},
	}}
	m := New(loader, r, []string{"INPUT", "OUTPUT", "FORWARD", "DOCKER"}, nil)
	m.setChain("DOCKER")
	if m.Query().Chain != "DOCKER" {
		t.Fatal(m.Query().Chain)
	}
	loader.res = iptables.ParseResult{Rules: r, Chains: []string{"INPUT", "OUTPUT", "FORWARD"}}
	m = press(m, "r")
	if m.Query().Chain != "" {
		t.Fatalf("chain=%q", m.Query().Chain)
	}
	if m.chainIndex != 0 {
		t.Fatalf("index=%d", m.chainIndex)
	}
	if m.status != "chain DOCKER gone, showing ALL" {
		t.Fatalf("status=%q", m.status)
	}
	if m.statusErr {
		t.Fatal("gone chain is not an error")
	}
}

func TestReloadDropsMissingChainKeepsWarnings(t *testing.T) {
	r := rules()
	loader := &stubLoader{res: iptables.ParseResult{
		Rules:  r,
		Chains: []string{"INPUT", "OUTPUT", "FORWARD", "DOCKER"},
	}}
	m := New(loader, r, []string{"INPUT", "OUTPUT", "FORWARD", "DOCKER"}, nil)
	m.setChain("DOCKER")
	loader.res = iptables.ParseResult{
		Rules:    r,
		Chains:   []string{"INPUT", "OUTPUT", "FORWARD"},
		Warnings: []string{"skipping malformed rule: -A INPUT", "skipping unexpected line: foo"},
	}
	m = press(m, "r")
	if m.Query().Chain != "" {
		t.Fatalf("chain=%q", m.Query().Chain)
	}
	want := "chain DOCKER gone, showing ALL; skipping malformed rule: -A INPUT; skipping unexpected line: foo"
	if m.status != want {
		t.Fatalf("status=%q want %q", m.status, want)
	}
	if m.statusErr {
		t.Fatal("gone chain is not an error")
	}
}

func TestReloadKeepsExistingChain(t *testing.T) {
	r := rules()
	loader := &stubLoader{res: iptables.ParseResult{Rules: r, Chains: testChains()}}
	m := New(loader, r, testChains(), nil)
	m.setChain("OUTPUT")
	m = press(m, "r")
	if m.Query().Chain != "OUTPUT" {
		t.Fatal(m.Query().Chain)
	}
	if m.statusErr {
		t.Fatal(m.status)
	}
}

func TestChainOverlayScrolls(t *testing.T) {
	chains := make([]string, 30)
	for i := range chains {
		chains[i] = fmt.Sprintf("C%d", i)
	}
	r := rules()
	m := New(stubLoader{}, r, chains, nil)
	next, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 12})
	m = next.(Model)
	m = press(m, "c")
	m = press(m, "G")
	got := stripANSI(m.View().Content)
	if strings.Contains(got, "▸ ALL") {
		t.Fatalf("scrolled overlay still shows ALL:\n%s", got)
	}
	if !strings.Contains(got, "C29") {
		t.Fatalf("last chain missing:\n%s", got)
	}
}

func TestChainOverlayResizeKeepsHighlightVisible(t *testing.T) {
	chains := make([]string, 30)
	for i := range chains {
		chains[i] = fmt.Sprintf("C%d", i)
	}
	r := rules()
	m := New(stubLoader{}, r, chains, nil)
	next, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 50})
	m = next.(Model)
	m = press(m, "c")
	m = press(m, "G")
	if m.chainOffset != 0 {
		t.Fatalf("list should fit at height 50, offset=%d", m.chainOffset)
	}
	next, _ = m.Update(tea.WindowSizeMsg{Width: 80, Height: 12})
	m = next.(Model)
	got := stripANSI(m.View().Content)
	if strings.Contains(got, "▸ ALL") {
		t.Fatalf("shrink left ▸ on ALL:\n%s", got)
	}
	if !strings.Contains(got, "▸ C29") {
		t.Fatalf("last chain highlight missing after shrink:\n%s", got)
	}
}

func TestReloadDropsMissingChainResetsOverlay(t *testing.T) {
	chains := make([]string, 30)
	for i := range chains {
		chains[i] = fmt.Sprintf("C%d", i)
	}
	r := rules()
	loader := &stubLoader{res: iptables.ParseResult{Rules: r, Chains: chains}}
	m := New(loader, r, chains, nil)
	next, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 12})
	m = next.(Model)
	m = press(m, "c")
	m = press(m, "G")
	if m.chainOffset == 0 {
		t.Fatal("expected scrolled overlay")
	}
	last := chains[len(chains)-1]
	if m.Query().Chain != last {
		t.Fatalf("chain=%q", m.Query().Chain)
	}
	loader.res = iptables.ParseResult{Rules: r, Chains: []string{"INPUT", "OUTPUT", "FORWARD"}}
	m = press(m, "r")
	if m.Query().Chain != "" {
		t.Fatalf("chain=%q", m.Query().Chain)
	}
	if m.chainIndex != 0 {
		t.Fatalf("index=%d", m.chainIndex)
	}
	got := stripANSI(m.View().Content)
	if !strings.Contains(got, "▸ ALL") {
		t.Fatalf("overlay should show ▸ ALL:\n%s", got)
	}
	gotH := m.table.Height()
	m.resize()
	if m.table.Height() != gotH {
		t.Fatalf("table height=%d after reload, resize wants %d", gotH, m.table.Height())
	}
}
