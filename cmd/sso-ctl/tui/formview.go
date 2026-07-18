package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/snaplink/sso/cmd/sso-ctl/apiclient"
)

type formMode int

const (
	formModeCreate formMode = iota
	formModeEdit
)

// formModel is a sequential set of textinput fields driven by an
// entityDescriptor's CreateFields/EditFields. It knows nothing about HTTP
// beyond calling createItem/updateItem in api.go — the descriptor supplies
// every entity-specific detail (which fields, which endpoint, how to parse
// each field back into a JSON payload).
type formModel struct {
	client     *apiclient.Client
	descriptor entityDescriptor
	mode       formMode
	existing   map[string]any
	specs      []fieldSpec
	inputs     []textinput.Model
	focus      int
	status     string
}

func newFormModel(client *apiclient.Client, d entityDescriptor, mode formMode, existing map[string]any) formModel {
	var specs []fieldSpec
	if mode == formModeCreate {
		specs = d.CreateFields()
	} else {
		specs = d.EditFields(existing)
	}
	inputs := make([]textinput.Model, len(specs))
	for i, spec := range specs {
		ti := textinput.New()
		ti.Placeholder = spec.Label
		ti.SetValue(spec.Initial)
		ti.CharLimit = 512
		ti.Width = 60
		inputs[i] = ti
	}
	if len(inputs) > 0 {
		inputs[0].Focus()
	}
	return formModel{client: client, descriptor: d, mode: mode, existing: existing, specs: specs, inputs: inputs}
}

func (m formModel) Update(msg tea.Msg) (formModel, tea.Cmd, action, any) {
	switch msg := msg.(type) {
	case opDoneMsg:
		return m.handleOpDone(msg)
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil, actionNone, nil
}

func (m formModel) handleOpDone(msg opDoneMsg) (formModel, tea.Cmd, action, any) {
	if msg.err != nil {
		m.status = "Error: " + msg.err.Error()
		return m, nil, actionNone, nil
	}
	return m, nil, actionSubmitted, msg.label
}

func (m formModel) handleKey(msg tea.KeyMsg) (formModel, tea.Cmd, action, any) {
	if len(m.inputs) == 0 {
		if msg.String() == "esc" {
			return m, nil, actionCancel, nil
		}
		return m, nil, actionNone, nil
	}
	switch msg.String() {
	case "esc":
		return m, nil, actionCancel, nil
	case "ctrl+s":
		return m, m.submitCmd(), actionNone, nil
	case "tab", "down":
		m.moveFocus(1)
		return m, nil, actionNone, nil
	case "shift+tab", "up":
		m.moveFocus(-1)
		return m, nil, actionNone, nil
	case "enter":
		if m.focus == len(m.inputs)-1 {
			return m, m.submitCmd(), actionNone, nil
		}
		m.moveFocus(1)
		return m, nil, actionNone, nil
	}
	var cmd tea.Cmd
	m.inputs[m.focus], cmd = m.inputs[m.focus].Update(msg)
	return m, cmd, actionNone, nil
}

func (m *formModel) moveFocus(delta int) {
	n := len(m.inputs)
	if n == 0 {
		return
	}
	m.inputs[m.focus].Blur()
	m.focus = ((m.focus+delta)%n + n) % n
	m.inputs[m.focus].Focus()
}

// submitCmd snapshots the current field values into a tea.Cmd closure so the
// HTTP call runs off the update loop, exactly like fetchCmd/deleteCmd in
// listview.go.
func (m formModel) submitCmd() tea.Cmd {
	raws := make([]string, len(m.inputs))
	for i, ti := range m.inputs {
		raws[i] = ti.Value()
	}
	payload := buildPayload(m.specs, raws)
	client, d, mode, existing := m.client, m.descriptor, m.mode, m.existing
	return func() tea.Msg {
		if mode == formModeCreate {
			label, err := createItem(client, d, payload)
			return opDoneMsg{verb: "create", label: label, err: err}
		}
		id := asString(existing["id"])
		label, err := updateItem(client, d, id, payload)
		return opDoneMsg{verb: "update", label: label, err: err}
	}
}

func (m formModel) View() string {
	var b strings.Builder
	title := fmt.Sprintf("%s — %s", m.descriptor.Label, formModeLabel(m.mode))
	b.WriteString(titleStyle.Render(title))
	b.WriteString("\n\n")
	for i, spec := range m.specs {
		style := blurredInputStyle
		if i == m.focus {
			style = focusedInputStyle
		}
		b.WriteString(labelStyle.Render(spec.Label))
		b.WriteString("\n")
		b.WriteString(style.Render(m.inputs[i].View()))
		b.WriteString("\n\n")
	}
	if m.status != "" {
		b.WriteString(errStyle.Render(m.status))
		b.WriteString("\n")
	}
	b.WriteString(helpStyle.Render("tab/shift+tab:move field  enter:next/submit  ctrl+s:submit  esc:cancel"))
	return b.String()
}

func formModeLabel(mode formMode) string {
	if mode == formModeCreate {
		return "New"
	}
	return "Edit"
}
