package scim

import (
	"net/http"
	"strings"
)

// SCIM-relative path dispatch helpers, split from handler.go to keep that
// (large, exempted) file from growing and to bring ServeHTTP under the
// cyclomatic-complexity budget. Each helper owns one route family and
// returns true when it handled the request, so ServeHTTP reads as an
// ordered list of route matchers.

// dispatchMeta handles the read-only discovery routes (ServiceProviderConfig,
// Schemas) and the Bulk/Me aliases.
func (h *Handler) dispatchMeta(w http.ResponseWriter, r *http.Request, rel string) bool {
	switch {
	case rel == pathServiceProviderConfig && r.Method == http.MethodGet:
		h.writeJSON(w, http.StatusOK, serviceProviderConfig())
	case rel == pathSchemas && r.Method == http.MethodGet:
		// GET /Schemas returns the implemented schemas as a ListResponse
		// (RFC 7643 §7 / RFC 7644 §4): connectors enumerate here. Group is
		// advertised only when WithGroups wired it, so a connector doesn't
		// push groups to a deployment that drops them.
		schemas := []SchemaResource{userSchema()}
		if h.groups != nil {
			schemas = append(schemas, groupSchema())
		}
		h.writeJSON(w, http.StatusOK, schemasListResponse(schemas))
	case rel == pathBulk && r.Method == http.MethodPost:
		h.bulk(w, r)
	case rel == pathMe:
		h.me(w, r)
	default:
		return false
	}
	return true
}

// dispatchUsers handles the /Users collection and /Users/{id} item routes.
func (h *Handler) dispatchUsers(w http.ResponseWriter, r *http.Request, rel string) bool {
	switch {
	case rel == pathUsers || rel == pathUsers+"/":
		switch r.Method {
		case http.MethodPost:
			h.createUser(w, r)
		case http.MethodGet:
			h.listUsers(w, r)
		default:
			h.writeError(w, newError(http.StatusMethodNotAllowed, "", "method not allowed on /Users"))
		}
	case strings.HasPrefix(rel, pathUsers+"/"):
		id := strings.TrimPrefix(rel, pathUsers+"/")
		// A nested segment (".../Users/a/b") is not a single resource id.
		if id == "" || strings.Contains(id, "/") {
			h.writeError(w, newError(http.StatusNotFound, "", "resource not found"))
			return true
		}
		h.dispatchUserItem(w, r, id)
	default:
		return false
	}
	return true
}

// dispatchUserItem routes a method against a single /Users/{id} resource.
func (h *Handler) dispatchUserItem(w http.ResponseWriter, r *http.Request, id string) {
	switch r.Method {
	case http.MethodGet:
		h.getUser(w, r, id)
	case http.MethodPut:
		h.replaceUser(w, r, id)
	case http.MethodPatch:
		h.patchUser(w, r, id)
	case http.MethodDelete:
		h.deleteUser(w, r, id)
	default:
		h.writeError(w, newError(http.StatusMethodNotAllowed, "", "method not allowed on /Users/{id}"))
	}
}

// dispatchGroups handles the /Groups collection and /Groups/{id} item routes.
// It is only consulted when WithGroups wired a permissions.Provider; with
// groups unmounted these paths fall through to the not-found default.
func (h *Handler) dispatchGroups(w http.ResponseWriter, r *http.Request, rel string) bool {
	if h.groups == nil {
		return false
	}
	switch {
	case rel == pathGroups || rel == pathGroups+"/":
		switch r.Method {
		case http.MethodPost:
			h.createGroup(w, r)
		case http.MethodGet:
			h.listGroups(w, r)
		default:
			h.writeError(w, newError(http.StatusMethodNotAllowed, "", "method not allowed on /Groups"))
		}
	case strings.HasPrefix(rel, pathGroups+"/"):
		id := strings.TrimPrefix(rel, pathGroups+"/")
		if id == "" || strings.Contains(id, "/") {
			h.writeError(w, newError(http.StatusNotFound, "", "resource not found"))
			return true
		}
		h.dispatchGroupItem(w, r, id)
	default:
		return false
	}
	return true
}

// dispatchGroupItem routes a method against a single /Groups/{id} resource.
func (h *Handler) dispatchGroupItem(w http.ResponseWriter, r *http.Request, id string) {
	switch r.Method {
	case http.MethodGet:
		h.getGroup(w, r, id)
	case http.MethodPut:
		h.replaceGroup(w, r, id)
	case http.MethodPatch:
		h.patchGroup(w, r, id)
	case http.MethodDelete:
		h.deleteGroup(w, r, id)
	default:
		h.writeError(w, newError(http.StatusMethodNotAllowed, "", "method not allowed on /Groups/{id}"))
	}
}
