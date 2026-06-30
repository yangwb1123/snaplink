package scim

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// bulkCapture is a minimal in-memory http.ResponseWriter used to replay a bulk
// operation through the handler's own dispatch and capture its status + body
// instead of writing to the client. Avoids importing net/http/httptest into
// non-test code.
type bulkCapture struct {
	hdr  http.Header
	code int
	body bytes.Buffer
}

func (c *bulkCapture) Header() http.Header {
	if c.hdr == nil {
		c.hdr = http.Header{}
	}
	return c.hdr
}
func (c *bulkCapture) WriteHeader(code int) {
	if c.code == 0 {
		c.code = code
	}
}
func (c *bulkCapture) Write(b []byte) (int, error) {
	if c.code == 0 {
		c.code = http.StatusOK
	}
	return c.body.Write(b)
}

// SCIM Bulk schema URNs (RFC 7644 §3.7).
const (
	SchemaBulkRequest  = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"
	SchemaBulkResponse = "urn:ietf:params:scim:api:messages:2.0:BulkResponse"
)

// pathBulk is the SCIM-relative Bulk route.
const pathBulk = "/Bulk"

// Bulk limits advertised in ServiceProviderConfig and enforced by the handler.
// Conservative defaults — an operator fronting a huge directory can raise them
// by forking, but unbounded bulk is a memory-amplification vector.
const (
	bulkMaxOperations  = 1000
	bulkMaxPayloadSize = 1 << 20 // 1 MiB
)

// BulkRequest is the POST /Bulk envelope (RFC 7644 §3.7).
type BulkRequest struct {
	Schemas []string `json:"schemas"`
	// FailOnErrors: stop processing after this many errored operations.
	// nil/absent or <=0 means process every operation (RFC 7644 §3.7).
	FailOnErrors *int            `json:"failOnErrors,omitempty"`
	Operations   []BulkOperation `json:"Operations"`
}

// BulkOperation is one entry of a BulkRequest/BulkResponse. Request entries
// carry method/bulkId/path/data; response entries carry method/bulkId/
// location/status/response. One struct with omitempty serves both (matching
// the RFC examples).
type BulkOperation struct {
	Method   string          `json:"method"`
	BulkID   string          `json:"bulkId,omitempty"`
	Path     string          `json:"path,omitempty"`
	Data     json.RawMessage `json:"data,omitempty"`
	Location string          `json:"location,omitempty"`
	Status   string          `json:"status,omitempty"`
	Response json.RawMessage `json:"response,omitempty"`
}

// BulkResponse is the POST /Bulk result envelope (RFC 7644 §3.7).
type BulkResponse struct {
	Schemas    []string        `json:"schemas"`
	Operations []BulkOperation `json:"Operations"`
}

// bulk handles POST /Bulk (RFC 7644 §3.7). Each operation is replayed through
// the handler's own dispatch (via an in-memory recorder), so every per-resource
// rule — validation, uniqueness, audit, Groups — is reused with zero
// duplication. POST results feed a bulkId->id map; subsequent operations'
// "bulkId:<id>" references in their path and data are resolved before replay
// (RFC 7644 §3.7.2), enabling create-then-reference within one request.
func (h *Handler) bulk(w http.ResponseWriter, r *http.Request) {
	req, ok := h.decodeBulkRequest(w, r)
	if !ok {
		return
	}

	failOnErrors := 0
	if req.FailOnErrors != nil && *req.FailOnErrors > 0 {
		failOnErrors = *req.FailOnErrors
	}

	bulkIDs := map[string]string{} // client bulkId -> server-assigned resource id
	respOps := make([]BulkOperation, 0, len(req.Operations))
	errCount := 0

	for _, op := range req.Operations {
		rop, errored := h.runBulkOp(r, op, bulkIDs)
		respOps = append(respOps, rop)
		if errored {
			errCount++
		}
		if failOnErrors > 0 && errCount >= failOnErrors {
			break
		}
	}

	h.writeJSON(w, http.StatusOK, BulkResponse{
		Schemas:    []string{SchemaBulkResponse},
		Operations: respOps,
	})
}

// decodeBulkRequest reads, bounds, and validates the POST /Bulk envelope
// (RFC 7644 §3.7): it caps the payload size and operation count (memory-
// amplification guards) and rejects a malformed or empty Operations list. On
// failure it writes the SCIM error and returns ok=false.
func (h *Handler) decodeBulkRequest(w http.ResponseWriter, r *http.Request) (BulkRequest, bool) {
	// Bound the payload before reading it all into memory.
	raw, err := io.ReadAll(io.LimitReader(r.Body, bulkMaxPayloadSize+1))
	if err != nil {
		h.writeError(w, newError(http.StatusBadRequest, scimTypeInvalidSyntax, "could not read bulk body"))
		return BulkRequest{}, false
	}
	if len(raw) > bulkMaxPayloadSize {
		h.writeError(w, newError(http.StatusRequestEntityTooLarge, "", "bulk payload exceeds maxPayloadSize"))
		return BulkRequest{}, false
	}
	var req BulkRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		h.writeError(w, newError(http.StatusBadRequest, scimTypeInvalidSyntax, "malformed BulkRequest"))
		return BulkRequest{}, false
	}
	if len(req.Operations) == 0 {
		h.writeError(w, newError(http.StatusBadRequest, scimTypeInvalidValue, "BulkRequest.Operations is required and non-empty"))
		return BulkRequest{}, false
	}
	if len(req.Operations) > bulkMaxOperations {
		h.writeError(w, newError(http.StatusRequestEntityTooLarge, "", "bulk operation count exceeds maxOperations"))
		return BulkRequest{}, false
	}
	return req, true
}

// runBulkOp executes one bulk operation by replaying it through the handler's
// own dispatch, returning the response entry and whether it errored. It
// resolves "bulkId:<id>" references against prior POSTs and, on a successful
// POST, records the new resource id in bulkIDs so later operations can
// reference it (RFC 7644 §3.7.2).
func (h *Handler) runBulkOp(r *http.Request, op BulkOperation, bulkIDs map[string]string) (BulkOperation, bool) {
	method := strings.ToUpper(strings.TrimSpace(op.Method))
	rop := BulkOperation{Method: op.Method, BulkID: op.BulkID}
	// RFC 7644 §3.7.2: a POST operation MUST carry a bulkId.
	if method == http.MethodPost && op.BulkID == "" {
		rop.Status = strconv.Itoa(http.StatusBadRequest)
		rop.Response = marshalErr(newError(http.StatusBadRequest, scimTypeInvalidValue, "POST bulk operation requires a bulkId"))
		return rop, true
	}

	// RFC 7644 §3.7.2 allows any path except /Bulk itself — allowing recursive
	// /Bulk dispatch causes unbounded goroutine-stack growth (DoS).
	// URL-decode before comparing: http.NewRequestWithContext decodes
	// percent-encoded paths (e.g. /%42ulk → /Bulk) so the router still
	// routes them to h.bulk even when EqualFold on the raw string passes.
	path := strings.TrimSpace(op.Path)
	if decoded, err := url.PathUnescape(path); err == nil {
		path = decoded
	}
	if strings.EqualFold(path, pathBulk) {
		rop.Status = strconv.Itoa(http.StatusBadRequest)
		rop.Response = marshalErr(newError(http.StatusBadRequest, scimTypeInvalidValue, "/Bulk is not a valid target for a bulk operation"))
		return rop, true
	}
	// Resolve "bulkId:<id>" references (path + data) against prior POSTs.
	path = resolveBulkRefs(path, bulkIDs)
	data := op.Data
	if len(data) > 0 {
		data = json.RawMessage(resolveBulkRefs(string(data), bulkIDs))
	}

	// Replay the operation through the handler's own dispatch.
	rec, err := h.execBulkSubrequest(r, method, path, data)
	if err != nil {
		rop.Status = strconv.Itoa(http.StatusBadRequest)
		rop.Response = marshalErr(newError(http.StatusBadRequest, scimTypeInvalidValue, "invalid operation method or path"))
		return rop, true
	}

	return processBulkCapture(rop, rec, method, bulkIDs)
}

// processBulkCapture stamps the HTTP status onto rop and, on success, extracts
// the created resource id+location and maps the bulkId for later references.
// Success bodies are omitted (RFC 7644 §3.7 examples); location suffices.
func processBulkCapture(rop BulkOperation, rec *bulkCapture, method string, bulkIDs map[string]string) (BulkOperation, bool) {
	rop.Status = strconv.Itoa(rec.code)
	if rec.code >= 200 && rec.code < 300 {
		id, loc := createdIDAndLocation(rec.body.Bytes())
		if loc != "" {
			rop.Location = loc
		}
		if method == http.MethodPost && rop.BulkID != "" && id != "" {
			bulkIDs[rop.BulkID] = id
		}
		return rop, false
	}
	rop.Response = append(json.RawMessage(nil), rec.body.Bytes()...)
	return rop, true
}

// execBulkSubrequest builds a sub-request for the given method/path/data and
// dispatches it through the handler's own ServeHTTP, capturing the response.
// Returns an error only when the request itself is malformed (invalid method
// or path) — an HTTP error from the sub-handler is captured in *bulkCapture.
func (h *Handler) execBulkSubrequest(r *http.Request, method, path string, data json.RawMessage) (*bulkCapture, error) {
	sreq, err := http.NewRequestWithContext(r.Context(), method, h.basePath+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	sreq.Header.Set("Content-Type", contentTypeSCIM)
	rec := &bulkCapture{}
	h.ServeHTTP(rec, sreq)
	return rec, nil
}

// me handles the SCIM /Me alias (RFC 7644 §3.11): it resolves the request to
// the authenticated subject's user id (via the wired meResolver) and dispatches
// GET/PUT/PATCH/DELETE against that user's OWN resource, reusing the per-user
// handlers. Without a resolver wired, /Me is 501 (the handler can't know the
// caller); without a resolvable subject it is 401.
func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	if h.meResolver == nil {
		h.writeError(w, newError(http.StatusNotImplemented, "", "/Me is not enabled on this deployment"))
		return
	}
	id, ok := h.meResolver(r)
	if !ok || id == "" {
		h.writeError(w, newError(http.StatusUnauthorized, "", "no authenticated subject for /Me"))
		return
	}
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
		h.writeError(w, newError(http.StatusMethodNotAllowed, "", "method not allowed on /Me"))
	}
}

// resolveBulkRefs replaces every "bulkId:<key>" token with the resolved
// resource id for each known bulkId. Keys are applied longest-first so a
// bulkId that is a prefix of another (e.g. "a" vs "ab") can't corrupt the
// longer token.
func resolveBulkRefs(s string, bulkIDs map[string]string) string {
	if s == "" || len(bulkIDs) == 0 || !strings.Contains(s, "bulkId:") {
		return s
	}
	keys := make([]string, 0, len(bulkIDs))
	for k := range bulkIDs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	for _, k := range keys {
		s = strings.ReplaceAll(s, "bulkId:"+k, bulkIDs[k])
	}
	return s
}

// createdIDAndLocation extracts the id + meta.location from a create/replace
// response body so Bulk can report the location and resolve bulkId references.
func createdIDAndLocation(body []byte) (id, location string) {
	var r struct {
		ID   string `json:"id"`
		Meta struct {
			Location string `json:"location"`
		} `json:"meta"`
	}
	if json.Unmarshal(body, &r) != nil {
		return "", ""
	}
	return r.ID, r.Meta.Location
}

// marshalErr renders a SCIM ErrorResponse as a raw JSON message for embedding
// in a BulkResponse operation.
func marshalErr(e ErrorResponse) json.RawMessage {
	b, err := json.Marshal(e)
	if err != nil {
		return json.RawMessage(`{"detail":"internal error"}`)
	}
	return b
}
