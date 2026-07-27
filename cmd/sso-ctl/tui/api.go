package tui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/yangwb1123/snaplink/cmd/sso-ctl/apiclient"
)

// listFetchedMsg and opDoneMsg are the tea.Msg results of the async HTTP
// calls kicked off by listViewModel.fetchCmd/deleteCmd and
// formModel.submitCmd. Keeping the HTTP calls as plain functions (rather
// than methods that also touch bubbletea state) is what makes them safe to
// run inside a tea.Cmd closure off the update loop.
type listFetchedMsg struct {
	items []genericItem
	err   error
}

type opDoneMsg struct {
	verb  string
	label string
	err   error
}

// fetchItems GETs an entity's list endpoint and decodes each row via the
// descriptor's Row func. A row that doesn't decode to an object is skipped
// rather than failing the whole fetch — one malformed record shouldn't hide
// every other one.
func fetchItems(client *apiclient.Client, d entityDescriptor) ([]genericItem, error) {
	resp, err := client.Get(d.ListPath)
	if err != nil {
		return nil, err
	}
	body, err := apiclient.ReadBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", apiErrorMessage(resp.StatusCode, body))
	}
	var envelope map[string]any
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	raw, _ := envelope[d.ItemsKey].([]any)
	items := make([]genericItem, 0, len(raw))
	for _, r := range raw {
		obj, ok := r.(map[string]any)
		if !ok {
			continue
		}
		id, title, desc := d.Row(obj)
		items = append(items, genericItem{id: id, title: title, desc: desc, raw: obj})
	}
	return items, nil
}

func createItem(client *apiclient.Client, d entityDescriptor, payload map[string]any) (string, error) {
	resp, err := client.Post(d.CreatePath, payload)
	if err != nil {
		return "", err
	}
	return decodeItemResponse(resp, d, "Created")
}

// updateItem uses client.Do directly — apiclient has no Put() convenience
// wrapper.
func updateItem(client *apiclient.Client, d entityDescriptor, id string, payload map[string]any) (string, error) {
	resp, err := client.Do(http.MethodPut, d.ItemPath(id), payload)
	if err != nil {
		return "", err
	}
	return decodeItemResponse(resp, d, "Updated")
}

func deleteItem(client *apiclient.Client, d entityDescriptor, id, title string) (string, error) {
	resp, err := client.Delete(d.ItemPath(id))
	if err != nil {
		return "", err
	}
	body, err := apiclient.ReadBody(resp)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s", apiErrorMessage(resp.StatusCode, body))
	}
	return fmt.Sprintf("Deleted %s %s", singular(d.Label), title), nil
}

// decodeItemResponse unwraps the admin API's single-object envelope (e.g.
// {"tenant": {...}}) and builds the status-line label from the entity's own
// Row func, so "Created tenant acme" always reflects what the server
// actually stored, not just what the form submitted.
func decodeItemResponse(resp *http.Response, d entityDescriptor, verb string) (string, error) {
	body, err := apiclient.ReadBody(resp)
	if err != nil {
		return "", err
	}
	// The admin API's write endpoints report success as plain HTTP 200
	// (see entitiescmd's doWrite), not 201.
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s", apiErrorMessage(resp.StatusCode, body))
	}
	var envelope map[string]any
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	obj, _ := envelope[d.ItemKey].(map[string]any)
	_, title, _ := d.Row(obj)
	return fmt.Sprintf("%s %s %s", verb, singular(d.Label), title), nil
}

func singular(label string) string {
	return strings.TrimSuffix(label, "s")
}

// apiErrorMessage prefers a decoded error/message field (grpc-gateway's
// google.rpc.Status shape) and falls back to the raw body so a malformed or
// unexpected error payload is never silently swallowed.
func apiErrorMessage(status int, body []byte) string {
	var parsed struct {
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil {
		if parsed.Message != "" {
			return fmt.Sprintf("HTTP %d: %s", status, parsed.Message)
		}
		if parsed.Error != "" {
			return fmt.Sprintf("HTTP %d: %s", status, parsed.Error)
		}
	}
	return fmt.Sprintf("HTTP %d: %s", status, string(body))
}
