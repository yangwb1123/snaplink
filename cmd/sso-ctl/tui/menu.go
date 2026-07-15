package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
)

// menuItem adapts an entityDescriptor to list.DefaultItem for the top-level
// menu.
type menuItem struct {
	descriptor entityDescriptor
}

func (i menuItem) FilterValue() string { return i.descriptor.Label }
func (i menuItem) Title() string       { return i.descriptor.Label }
func (i menuItem) Description() string { return "Manage " + strings.ToLower(i.descriptor.Label) }

type menuModel struct {
	list list.Model
}

func newMenuModel(width, height int) menuModel {
	items := make([]list.Item, len(registry))
	for i, d := range registry {
		items[i] = menuItem{descriptor: d}
	}
	l := list.New(items, list.NewDefaultDelegate(), width, safeHeight(height-4))
	l.Title = "sso-ctl — SSO Admin"
	return menuModel{list: l}
}

func (m menuModel) Update(msg tea.Msg) (menuModel, tea.Cmd, action, any) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.list.SetSize(msg.Width, safeHeight(msg.Height-4))
		return m, nil, actionNone, nil
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd, actionNone, nil
}

func (m menuModel) handleKey(msg tea.KeyMsg) (menuModel, tea.Cmd, action, any) {
	switch msg.String() {
	case "enter":
		if sel, ok := m.list.SelectedItem().(menuItem); ok {
			return m, nil, actionOpenList, sel.descriptor
		}
		return m, nil, actionNone, nil
	case "q", "esc":
		return m, nil, actionQuit, nil
	}
	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd, actionNone, nil
}

func (m menuModel) View() string {
	return m.list.View() + "\n" + helpStyle.Render("enter:select  q/esc:quit  ctrl+c:quit")
}
