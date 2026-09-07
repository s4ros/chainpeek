package tui

import (
	"strconv"
	"strings"

	"charm.land/lipgloss/v2"
)

// Vertical chrome consumed by the framed layout (not the table itself).
const (
	chromeTopBar    = 1
	chromeChips     = 1
	chromeTableRule = 1 // ├─┤ above the table
	chromeBottom    = 1
	chromeKeys      = 1
	chromeBase      = chromeTopBar + chromeChips + chromeBottom + chromeKeys
	overlayRule     = 1
	minTableHeight  = 3
	minFrameWidth   = 8
)

var (
	frameColor  = lipgloss.BrightBlack
	accentColor = lipgloss.Cyan

	frameStyle  = lipgloss.NewStyle().Foreground(frameColor)
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(accentColor)
	metaStyle   = lipgloss.NewStyle().Faint(true)
	sepStyle    = lipgloss.NewStyle().Faint(true).Foreground(frameColor)
	chipOnStyle = lipgloss.NewStyle().Reverse(true).Bold(true)
	emptyStyle  = lipgloss.NewStyle().Faint(true).Italic(true)
	keyStyle    = lipgloss.NewStyle().Faint(true)
	warnStyle   = lipgloss.NewStyle().Foreground(lipgloss.Yellow)
	errStyle    = lipgloss.NewStyle().Foreground(lipgloss.Red)
	okStyle     = lipgloss.NewStyle().Foreground(lipgloss.Green)
	headerStyle = lipgloss.NewStyle().Bold(true).Foreground(accentColor).Padding(0, 1)
)

func (m Model) frameWidth() int {
	if m.width > minFrameWidth {
		return m.width
	}
	if m.width > 0 {
		return m.width
	}
	return 80
}

func (m Model) innerWidth() int {
	w := m.frameWidth() - 2
	if w < 1 {
		return 1
	}
	return w
}

func (m Model) titleLeft() string {
	return titleStyle.Render("chainpeek") + metaStyle.Render("  v"+version)
}

func (m Model) titleRight() string {
	if m.showHelp {
		return metaStyle.Render("help")
	}
	return metaStyle.Render(strconv.Itoa(len(m.visible)) + "/" + strconv.Itoa(len(m.all)) + " rules")
}

func (m Model) chipsLine() string {
	sep := sepStyle.Render("  ·  ")
	chain := "chain:" + chainLabel(m.query.Chain) + " ▾"
	if m.chainFocus {
		chain = chipOnStyle.Render(chain)
	}
	return chain + sep + "action:" + actionLabel(m.query.Action) + sep + "sort:" + sortLabel(m.query.ByPort)
}

func topBar(width int, left, right string) string {
	return framedRule(width, "╭", "╮", left, right)
}

func bottomBar(width int) string {
	return framedRule(width, "╰", "╯", "", "")
}

func sectionRule(width int, title string) string {
	t := title
	if t != "" {
		t = titleStyle.Render(t)
	}
	return framedRule(width, "├", "┤", t, "")
}

// framedRule draws a full-width bar: corner + ─ titles ─ + corner.
func framedRule(width int, leftCorner, rightCorner, left, right string) string {
	if width < 2 {
		return frameStyle.Render(leftCorner + rightCorner)
	}
	innerW := width - 2

	leftBit := ""
	if left != "" {
		leftBit = frameStyle.Render("─ ") + left + " "
	}
	rightBit := ""
	if right != "" {
		rightBit = " " + right + frameStyle.Render(" ─")
	}

	fillN := innerW - lipgloss.Width(leftBit) - lipgloss.Width(rightBit)
	if fillN < 0 {
		rightBit = ""
		fillN = innerW - lipgloss.Width(leftBit)
	}
	if fillN < 0 {
		leftBit = truncateVisual(leftBit, innerW)
		fillN = innerW - lipgloss.Width(leftBit)
	}
	if fillN < 0 {
		fillN = 0
	}

	inner := leftBit + frameStyle.Render(strings.Repeat("─", fillN)) + rightBit
	if pad := innerW - lipgloss.Width(inner); pad > 0 {
		inner += frameStyle.Render(strings.Repeat("─", pad))
	}
	return frameStyle.Render(leftCorner) + inner + frameStyle.Render(rightCorner)
}

func boxLines(s string, innerW int) string {
	s = strings.TrimRight(s, "\n")
	bar := frameStyle.Render("│")
	if s == "" {
		return bar + strings.Repeat(" ", innerW) + bar
	}
	lines := strings.Split(s, "\n")
	var b strings.Builder
	for i, line := range lines {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(bar)
		b.WriteString(padInner(line, innerW))
		b.WriteString(bar)
	}
	return b.String()
}

func padInner(line string, innerW int) string {
	if innerW <= 0 {
		return ""
	}
	w := lipgloss.Width(line)
	switch {
	case w == innerW:
		return line
	case w < innerW:
		return line + strings.Repeat(" ", innerW-w)
	default:
		return truncateVisual(line, innerW)
	}
}

func padLeft(s string) string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return s
	}
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = " " + line
	}
	return strings.Join(lines, "\n")
}

func truncateVisual(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= max {
		return s
	}
	return lipgloss.NewStyle().MaxWidth(max).Render(s)
}
