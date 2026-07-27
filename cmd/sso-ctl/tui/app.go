package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/yangwb1123/snaplink/cmd/sso-ctl/apiclient"
)

// action is how a child screen tells appModel what navigation to perform
// after processing a message. Keeping this as a returned enum (rather than
// each screen mutating shared state) is what lets every screen stay an
// ordinary, independently testable bubbletea component.
type action int

const (
	actionNone action = iota
	actionQuit
	actionBack
	actionOpenList
	actionOpenCreateForm
	actionOpenEditForm
	actionCancel
	actionSubmitted
)

type screen int

const (
	screenMenu screen = iota
	screenList
	screenForm
)

// appModel is the root bubbletea model. It owns exactly one live child
// screen at a time and routes messages to it; screen transitions are driven
// by the action each child's Update returns.
type appModel struct {
	client        *apiclient.Client
	screen        screen
	menu          menuModel
	list          listViewModel
	form          formModel
	width, height int
}

func newAppModel(client *apiclient.Client) appModel {
	const defaultWidth, defaultHeight = 80, 24
	return appModel{
		client: client,
		screen: screenMenu,
		menu:   newMenuModel(defaultWidth, defaultHeight),
		width:  defaultWidth,
		height: defaultHeight,
	}
}

func (m appModel) Init() tea.Cmd { return nil }

func (m appModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// ctrl+c must quit from any screen, including mid-form or mid-confirm —
	// checked before dispatch so no child screen can swallow it.
	if k, ok := msg.(tea.KeyMsg); ok && k.String() == "ctrl+c" {
		return m, tea.Quit
	}
	if ws, ok := msg.(tea.WindowSizeMsg); ok {
		m.width, m.height = ws.Width, ws.Height
	}
	switch m.screen {
	case screenList:
		return m.updateList(msg)
	case screenForm:
		return m.updateForm(msg)
	default:
		return m.updateMenu(msg)
	}
}

func (m appModel) updateMenu(msg tea.Msg) (tea.Model, tea.Cmd) {
	next, cmd, act, payload := m.menu.Update(msg)
	m.menu = next
	if act == actionQuit {
		return m, tea.Quit
	}
	if act == actionOpenList {
		if d, ok := payload.(entityDescriptor); ok {
			m.list = newListViewModel(m.client, d, m.width, m.height)
			m.screen = screenList
			return m, tea.Batch(cmd, m.list.Init())
		}
	}
	return m, cmd
}

func (m appModel) updateList(msg tea.Msg) (tea.Model, tea.Cmd) {
	next, cmd, act, payload := m.list.Update(msg)
	m.list = next
	switch act {
	case actionBack:
		m.screen = screenMenu
	case actionOpenCreateForm:
		m.form = newFormModel(m.client, m.list.descriptor, formModeCreate, nil)
		m.screen = screenForm
	case actionOpenEditForm:
		if existing, ok := payload.(map[string]any); ok {
			m.form = newFormModel(m.client, m.list.descriptor, formModeEdit, existing)
			m.screen = screenForm
		}
	}
	return m, cmd
}

func (m appModel) updateForm(msg tea.Msg) (tea.Model, tea.Cmd) {
	next, cmd, act, payload := m.form.Update(msg)
	m.form = next
	switch act {
	case actionCancel:
		m.screen = screenList
	case actionSubmitted:
		m.screen = screenList
		if label, ok := payload.(string); ok {
			m.list.status = label
		}
		cmd = tea.Batch(cmd, m.list.fetchCmd())
	}
	return m, cmd
}

func (m appModel) View() string {
	switch m.screen {
	case screenList:
		return m.list.View()
	case screenForm:
		return m.form.View()
	default:
		return m.menu.View()
	}
}

// safeHeight keeps list.Model.SetSize from being handed a non-positive
// height before the first real WindowSizeMsg arrives (e.g. during tests
// that drive Update without a terminal attached).
func safeHeight(h int) int {
	if h < 3 {
		return 3
	}
	return h
}
