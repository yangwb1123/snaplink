package scimprovision

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/protocols/scim"
	"github.com/yangwb1123/snaplink/shared/security/securityverify"
)

// DefaultHTTPTimeout bounds a single outbound SCIM HTTP call when
// WithHTTPTimeout is not supplied.
const DefaultHTTPTimeout = 10 * time.Second

// pathUsersRel / pathGroupsRel are the downstream SCIM resource paths,
// relative to HTTPSCIMProvisioner.baseURL (RFC 7644 §3.2). Declared
// independently of protocols/scim's own unexported path consts because this
// package sits ALONGSIDE, not below, protocols/scim in the layer ordering —
// mirrors platform/lifecycle/webhook's validateHTTPSURL, which duplicates
// rather than imports for the same reason.
const (
	pathUsersRel  = "/Users"
	pathGroupsRel = "/Groups"
)

// HTTPSCIMProvisioner is the reference SCIMProvisioner: it POSTs, PUTs,
// PATCHes, and DELETEs to a single configured downstream SCIM 2.0 base URL,
// authenticating with a static bearer token (RFC 7644 §2's common auth
// model). Construct with NewHTTPSCIMProvisioner.
type HTTPSCIMProvisioner struct {
	baseURL string
	token   string
	client  *http.Client
	timeout time.Duration
}

// HTTPOption configures an HTTPSCIMProvisioner at construction.
type HTTPOption func(*HTTPSCIMProvisioner)

// WithBearerToken sets the static Authorization: Bearer token sent with
// every outbound request. Empty (the default) sends no Authorization
// header — only appropriate for a downstream that authenticates by other
// means (mTLS, network isolation).
func WithBearerToken(token string) HTTPOption {
	return func(p *HTTPSCIMProvisioner) { p.token = token }
}

// WithHTTPClient injects a custom *http.Client (connection reuse across
// deliveries, custom transport/proxy). A nil client is ignored.
func WithHTTPClient(c *http.Client) HTTPOption {
	return func(p *HTTPSCIMProvisioner) {
		if c != nil {
			p.client = c
		}
	}
}

// WithHTTPTimeout overrides the per-request timeout (DefaultHTTPTimeout).
// Values <= 0 are ignored.
func WithHTTPTimeout(d time.Duration) HTTPOption {
	return func(p *HTTPSCIMProvisioner) {
		if d > 0 {
			p.timeout = d
			if p.client != nil {
				p.client.Timeout = d
			}
		}
	}
}

// NewHTTPSCIMProvisioner builds an HTTPSCIMProvisioner targeting baseURL
// (the downstream SCIM 2.0 service root, e.g.
// "https://app.example.com/scim/v2"). A trailing slash is trimmed so path
// joins never produce a doubled "//".
func NewHTTPSCIMProvisioner(baseURL string, opts ...HTTPOption) *HTTPSCIMProvisioner {
	dialer := &securityverify.SSRFGuardedDialer{ErrPrefix: "scimprovision", Timeout: DefaultHTTPTimeout}
	p := &HTTPSCIMProvisioner{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		client: &http.Client{
			Timeout:       DefaultHTTPTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport:     dialer.Transport(),
		},
		timeout: DefaultHTTPTimeout,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

var _ SCIMProvisioner = (*HTTPSCIMProvisioner)(nil)

// StatusError carries a downstream non-2xx response so callers/logs see WHY
// a push failed. Body is truncated defensively — a misbehaving downstream
// returning an oversized error page must not blow up log lines.
type StatusError struct {
	Status int
	Body   string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("scimprovision: downstream returned %d: %s", e.Status, e.Body)
}

const maxErrorBodyBytes = 2048

// CreateUser implements SCIMProvisioner.
func (p *HTTPSCIMProvisioner) CreateUser(ctx context.Context, user scim.Resource) (scim.Resource, error) {
	user.ID = "" // server-assigned on create (RFC 7644 §3.3)
	var out scim.Resource
	err := p.doJSON(ctx, http.MethodPost, pathUsersRel, user, &out)
	return out, err
}

// ReplaceUser implements SCIMProvisioner, self-healing to CreateUser when
// the downstream has never seen this ExternalID (see doc.go).
func (p *HTTPSCIMProvisioner) ReplaceUser(ctx context.Context, user scim.Resource) (scim.Resource, error) {
	id, found, err := p.resolveID(ctx, pathUsersRel, user.ExternalID)
	if err != nil {
		return scim.Resource{}, err
	}
	if !found {
		return p.CreateUser(ctx, user)
	}
	var out scim.Resource
	err = p.doJSON(ctx, http.MethodPut, pathUsersRel+"/"+url.PathEscape(id), user, &out)
	return out, err
}

// DeleteUser implements SCIMProvisioner. Idempotent: an ExternalID the
// downstream never had (or already removed) is success, not an error.
func (p *HTTPSCIMProvisioner) DeleteUser(ctx context.Context, externalID string) error {
	id, found, err := p.resolveID(ctx, pathUsersRel, externalID)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	return p.doDelete(ctx, pathUsersRel+"/"+url.PathEscape(id))
}

// ReplaceGroupMembers implements SCIMProvisioner: a PATCH members+
// displayName "replace" (RFC 7644 §3.5.2) against the downstream group
// resolved by ExternalID, self-healing to a POST /Groups create when the
// downstream has never seen this group.
func (p *HTTPSCIMProvisioner) ReplaceGroupMembers(ctx context.Context, group scim.GroupResource) (scim.GroupResource, error) {
	id, found, err := p.resolveID(ctx, pathGroupsRel, group.ExternalID)
	if err != nil {
		return scim.GroupResource{}, err
	}
	if !found {
		var out scim.GroupResource
		err = p.doJSON(ctx, http.MethodPost, pathGroupsRel, group, &out)
		return out, err
	}
	patch, err := groupReplacePatch(group)
	if err != nil {
		return scim.GroupResource{}, err
	}
	var out scim.GroupResource
	err = p.doJSON(ctx, http.MethodPatch, pathGroupsRel+"/"+url.PathEscape(id), patch, &out)
	return out, err
}

// DeleteGroup implements SCIMProvisioner. Idempotent, same 404 contract as
// DeleteUser.
func (p *HTTPSCIMProvisioner) DeleteGroup(ctx context.Context, externalID string) error {
	id, found, err := p.resolveID(ctx, pathGroupsRel, externalID)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	return p.doDelete(ctx, pathGroupsRel+"/"+url.PathEscape(id))
}

// groupReplacePatch builds the SCIM PATCH body (RFC 7644 §3.5.2) that
// reconciles displayName + membership in one request, reusing
// scim.PatchRequest/PatchOperation/GroupMember — the exact types
// protocols/scim's own PATCH handler parses — rather than a parallel shape.
func groupReplacePatch(group scim.GroupResource) (scim.PatchRequest, error) {
	nameVal, err := json.Marshal(group.DisplayName)
	if err != nil {
		return scim.PatchRequest{}, fmt.Errorf("scimprovision: marshal displayName: %w", err)
	}
	membersVal, err := json.Marshal(group.Members)
	if err != nil {
		return scim.PatchRequest{}, fmt.Errorf("scimprovision: marshal members: %w", err)
	}
	return scim.PatchRequest{
		Schemas: []string{scim.SchemaPatchOp},
		Operations: []scim.PatchOperation{
			{Op: "replace", Path: "displayName", Value: nameVal},
			{Op: "replace", Path: "members", Value: membersVal},
		},
	}, nil
}

// idOnlyResource decodes just enough of a SCIM list envelope (RFC 7644
// §3.4.2) to resolve an id — shared across /Users and /Groups since both
// envelopes carry the same "Resources[].id" shape for this purpose.
type idOnlyResource struct {
	ID string `json:"id"`
}
type idOnlyListResponse struct {
	TotalResults int              `json:"totalResults"`
	Resources    []idOnlyResource `json:"Resources"`
}

// resolveID looks up the downstream id of the resource under resourcePath
// whose externalId equals externalID (RFC 7644 §3.4.2.2 filter), resolved
// FRESH on every call — see doc.go's "resolve fresh, no cache" note. ok=false
// (nil error) means no downstream resource carries that externalId yet.
func (p *HTTPSCIMProvisioner) resolveID(ctx context.Context, resourcePath, externalID string) (id string, ok bool, err error) {
	if strings.TrimSpace(externalID) == "" {
		return "", false, fmt.Errorf("scimprovision: empty externalId for %s lookup", resourcePath)
	}
	q := url.Values{}
	q.Set("filter", `externalId eq "`+escapeFilterValue(externalID)+`"`)
	q.Set("count", "1")
	var list idOnlyListResponse
	if err := p.doJSON(ctx, http.MethodGet, resourcePath+"?"+q.Encode(), nil, &list); err != nil {
		return "", false, err
	}
	if len(list.Resources) == 0 {
		return "", false, nil
	}
	return list.Resources[0].ID, true, nil
}

// escapeFilterValue escapes '\' and '"' per the SCIM filter grammar's quoted
// string (RFC 7644 §3.4.2.2 ABNF) so an externalID containing either can't
// break out of the filter's quoted comparison value.
func escapeFilterValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `"`, `\"`)
}

// doJSON sends method to baseURL+relPath, marshaling body when non-nil
// (skipped for GET/DELETE-shaped calls that pass nil), and decodes a 2xx
// response into out when out is non-nil. Every request carries the SCIM
// media type (RFC 7644 §3.1) and the configured bearer token, if any.
func (p *HTTPSCIMProvisioner) doJSON(ctx context.Context, method, relPath string, body, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("scimprovision: marshal request: %w", err)
		}
		reader = bytes.NewReader(b)
	}
	reqCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, method, p.baseURL+relPath, reader)
	if err != nil {
		return fmt.Errorf("scimprovision: build request: %w", err)
	}
	p.setHeaders(req, body != nil)
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("scimprovision: %s %s: %w", method, relPath, err)
	}
	defer resp.Body.Close()
	return decodeSCIMResponse(resp, out)
}

// doDelete sends DELETE relPath, treating a downstream 404 as success (the
// end state is already achieved — see SCIMProvisioner.DeleteUser).
func (p *HTTPSCIMProvisioner) doDelete(ctx context.Context, relPath string) error {
	reqCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodDelete, p.baseURL+relPath, nil)
	if err != nil {
		return fmt.Errorf("scimprovision: build request: %w", err)
	}
	p.setHeaders(req, false)
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("scimprovision: DELETE %s: %w", relPath, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	return decodeSCIMResponse(resp, nil)
}

// setHeaders stamps the SCIM media type + bearer auth common to every
// outbound request. hasBody additionally sets Content-Type (a GET/DELETE
// carries no request body to type).
func (p *HTTPSCIMProvisioner) setHeaders(req *http.Request, hasBody bool) {
	req.Header.Set("Accept", scim.ContentTypeSCIM)
	if hasBody {
		req.Header.Set("Content-Type", scim.ContentTypeSCIM)
	}
	if p.token != "" {
		req.Header.Set("Authorization", "Bearer "+p.token)
	}
}

// decodeSCIMResponse validates the status and, when out is non-nil, decodes
// the body into it. A non-2xx status returns *StatusError with a
// size-bounded body snippet.
func decodeSCIMResponse(resp *http.Response, out any) error {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		limited := io.LimitReader(resp.Body, maxErrorBodyBytes)
		b, _ := io.ReadAll(limited)
		return &StatusError{Status: resp.StatusCode, Body: string(b)}
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil && err != io.EOF {
		return fmt.Errorf("scimprovision: decode response: %w", err)
	}
	return nil
}
