package tui

import "github.com/charmbracelet/lipgloss"

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Padding(0, 1).
			Background(lipgloss.Color("62")).
			Foreground(lipgloss.Color("230"))

	statusStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))

	errStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))

	helpStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))

	confirmStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214"))

	labelStyle = lipgloss.NewStyle().Bold(true)

	focusedInputStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	blurredInputStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("246"))
)
