package tui

import (
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
)

func TestFramedRuleFitsWidth(t *testing.T) {
	left := titleStyle.Render("chainpeek") + metaStyle.Render("  v"+version)
	right := metaStyle.Render("4/4 rules")
	for _, w := range []int{2, 8, 20, 40, 80, 120, 200} {
		got := topBar(w, left, right)
		if lipgloss.Width(got) != w {
			t.Errorf("topBar(%d) visual width %d\n%s", w, lipgloss.Width(got), stripANSI(got))
		}
		bot := bottomBar(w)
		if lipgloss.Width(bot) != w {
			t.Errorf("bottomBar(%d) visual width %d\n%s", w, lipgloss.Width(bot), stripANSI(bot))
		}
		sec := sectionRule(w, "chain")
		if lipgloss.Width(sec) != w {
			t.Errorf("sectionRule(%d) visual width %d\n%s", w, lipgloss.Width(sec), stripANSI(sec))
		}
	}
}

func TestBoxLinesFitsWidth(t *testing.T) {
	inner := 40
	got := boxLines("short\n"+strings.Repeat("x", 80), inner)
	for i, line := range strings.Split(got, "\n") {
		if lipgloss.Width(line) != inner+2 {
			t.Errorf("line %d width %d want %d\n%s", i, lipgloss.Width(line), inner+2, stripANSI(line))
		}
	}
}

func TestPadLeft(t *testing.T) {
	if got := padLeft("a\nb"); got != " a\n b" {
		t.Fatalf("%q", got)
	}
}
