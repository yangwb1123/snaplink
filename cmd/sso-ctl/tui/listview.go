package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/snaplink/sso/cmd/sso-ctl/apiclient"
)

// listViewModel renders one entity type's records (fetched from the admin
// API) as a bubbles/list.Model and handles the n/e/d/r/esc keybindings
// documented on the tui package. Delete goes through an inline y/n
// sub-state (confirmDelete) rather than a separate screen, since it never
// needs its own layout.
type listViewModel struct {
	client        *apiclient.Client
	descriptor    entityDescriptor
	list          list.Model
	status        string
	err           string
	confirmDelete bool
	confirmTarget genericItem
}

func newListViewModel(client *apiclient.Client, d entityDescriptor, width, height int) listViewModel {
	l := list.New(nil, list.NewDefaultDelegate(), width, safeHeight(height-4))
	l.Title = d.Label
	return listViewModel{client: client, descriptor: d, list: l}
}

func (m listViewModel) Init() tea.Cmd {
	return m.fetchCmd()
}

func (m listViewModel) fetchCmd() tea.Cmd {
	client, d := m.client, m.descriptor
	return func() tea.Msg {
		items, err := fetchItems(client, d)
		return listFetchedMsg{items: items, err: err}
	}
}

func (m listViewModel) deleteCmd(target genericItem) tea.Cmd {
	client, d := m.client, m.descriptor
	return func() tea.Msg {
		label, err := deleteItem(client, d, target.id, target.title)
		return opDoneMsg{verb: "delete", label: label, err: err}
	}
}

func (m listViewModel) Update(msg tea.Msg) (listViewModel, tea.Cmd, action, any) {
	if m.confirmDelete {
		return m.handleConfirmKey(msg)
	}
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.list.SetSize(msg.Width, safeHeight(msg.Height-4))
		return m, nil, actionNone, nil
	case listFetchedMsg:
		return m.handleFetched(msg), nil, actionNone, nil
	case opDoneMsg:
		return m.handleOpDone(msg)
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd, actionNone, nil
}

func (m listViewModel) handleFetched(msg listFetchedMsg) listViewModel {
	if msg.err != nil {
		m.err = msg.err.Error()
		return m
	}
	m.err = ""
	items := make([]list.Item, len(msg.items))
	for i, it := range msg.items {
		items[i] = it
	}
	m.list.SetItems(items)
	return m
}

func (m listViewModel) handleOpDone(msg opDoneMsg) (listViewModel, tea.Cmd, action, any) {
	if msg.err != nil {
		m.status = "Error: " + msg.err.Error()
	} else {
		m.status = msg.label
	}
	// A create/update/delete may have changed rows or their order, so
	// re-fetch rather than patch the in-memory list.
	return m, m.fetchCmd(), actionNone, nil
}

func (m listViewModel) handleConfirmKey(msg tea.Msg) (listViewModel, tea.Cmd, action, any) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil, actionNone, nil
	}
	switch key.String() {
	case "y":
		m.confirmDelete = false
		return m, m.deleteCmd(m.confirmTarget), actionNone, nil
	case "n", "esc":
		m.confirmDelete = false
		m.status = "Delete cancelled"
	}
	return m, nil, actionNone, nil
}

func (m listViewModel) handleKey(msg tea.KeyMsg) (listViewModel, tea.Cmd, action, any) {
	switch msg.String() {
	case "esc", "q":
		return m, nil, actionBack, nil
	case "r":
		m.status = "Refreshing..."
		return m, m.fetchCmd(), actionNone, nil
	case "n":
		return m.startCreate()
	case "e":
		return m.startEdit()
	case "d":
		return m.startDelete()
	}
	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd, actionNone, nil
}

func (m listViewModel) startCreate() (listViewModel, tea.Cmd, action, any) {
	if m.descriptor.ReadOnly {
		m.status = m.descriptor.Label + " are read-only in this tool"
		return m, nil, actionNone, nil
	}
	return m, nil, actionOpenCreateForm, nil
}

func (m listViewModel) startEdit() (listViewModel, tea.Cmd, action, any) {
	if m.descriptor.ReadOnly {
		m.status = m.descriptor.Label + " are read-only in this tool"
		return m, nil, actionNone, nil
	}
	sel, ok := m.list.SelectedItem().(genericItem)
	if !ok {
		m.status = "No item selected"
		return m, nil, actionNone, nil
	}
	return m, nil, actionOpenEditForm, sel.raw
}

func (m listViewModel) startDelete() (listViewModel, tea.Cmd, action, any) {
	if m.descriptor.ReadOnly {
		m.status = m.descriptor.Label + " are read-only in this tool"
		return m, nil, actionNone, nil
	}
	sel, ok := m.list.SelectedItem().(genericItem)
	if !ok {
		m.status = "No item selected"
		return m, nil, actionNone, nil
	}
	m.confirmDelete = true
	m.confirmTarget = sel
	return m, nil, actionNone, nil
}

func (m listViewModel) View() string {
	var b strings.Builder
	b.WriteString(m.list.View())
	b.WriteString("\n")
	switch {
	case m.confirmDelete:
		b.WriteString(confirmStyle.Render(fmt.Sprintf("Delete %q? (y/n)", m.confirmTarget.title)))
		b.WriteString("\n")
	case m.err != "":
		b.WriteString(errStyle.Render("Error: " + m.err))
		b.WriteString("\n")
	case m.status != "":
		b.WriteString(statusStyle.Render(m.status))
		b.WriteString("\n")
	}
	b.WriteString(helpStyle.Render("n:new  e:edit  d:delete  r:refresh  esc/q:back  ctrl+c:quit"))
	return b.String()
}
