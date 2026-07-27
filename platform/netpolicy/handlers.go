package netpolicy

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// HandlerDeps is what the netpolicy HTTP handlers need. *sso.Server
// satisfies this via the accessor methods on Server.
type HandlerDeps interface {
	NetStore() Store
	NetClassifier() *Classifier
	Auditor() *audit.Recorder
	SrvLogger() spi.Logger
}

// Payload is the JSON payload for POST /api/v1/netpolicy/policies.
// Mirrors the Policy fields callers are allowed to set — Version
// and UpdatedAt are server-stamped.
type Payload struct {
	Name                string            `json:"name"`
	CIDRs               []string          `json:"cidrs,omitempty"`
	Hostnames           []string          `json:"hostnames,omitempty"`
	Priority            int32             `json:"priority,omitempty"`
	AdvertisedBaseURL   string            `json:"advertised_base_url,omitempty"`
	AdvertisedJWKSURL   string            `json:"advertised_jwks_url,omitempty"`
	AdvertisedLogoutURL string            `json:"advertised_logout_url,omitempty"`
	Metadata            map[string]string `json:"metadata,omitempty"`
}

func (p *Payload) toPolicy() *Policy {
	return &Policy{
		Name:                p.Name,
		CIDRs:               p.CIDRs,
		Hostnames:           p.Hostnames,
		Priority:            p.Priority,
		AdvertisedBaseURL:   p.AdvertisedBaseURL,
		AdvertisedJWKSURL:   p.AdvertisedJWKSURL,
		AdvertisedLogoutURL: p.AdvertisedLogoutURL,
		Metadata:            p.Metadata,
	}
}

// HandleList implements GET /api/v1/netpolicy/policies.
func HandleList(d HandlerDeps, ctx core.HandlerContext) {
	store := d.NetStore()
	if store == nil {
		ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: core.ErrNetPolicyNotConfigured})
		return
	}
	policies, err := store.List(ctx.Request().Context())
	if err != nil {
		d.SrvLogger().Error("netpolicy list", "error", err)
		ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: core.ErrInternal})
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{core.KeyNetPolicies: policies})
}

// HandleGet implements GET /api/v1/netpolicy/policies/:name.
func HandleGet(d HandlerDeps, ctx core.HandlerContext) {
	store := d.NetStore()
	if store == nil {
		ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: core.ErrNetPolicyNotConfigured})
		return
	}
	name := ctx.Param("name")
	if name == "" {
		ctx.JSON(http.StatusBadRequest, map[string]string{core.KeyError: core.ErrInvalidRequest})
		return
	}
	p, err := store.Get(ctx.Request().Context(), name)
	if errors.Is(err, ErrNotFound) {
		ctx.JSON(http.StatusNotFound, map[string]string{core.KeyError: core.ErrNetPolicyNotFound})
		return
	}
	if err != nil {
		d.SrvLogger().Error("netpolicy get", "error", err)
		ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: core.ErrInternal})
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{core.KeyNetPolicy: p})
}

// HandleApply implements POST /api/v1/netpolicy/policies.
func HandleApply(d HandlerDeps, ctx core.HandlerContext) {
	store := d.NetStore()
	if store == nil {
		ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: core.ErrNetPolicyNotConfigured})
		return
	}
	var payload Payload
	if err := ctx.Bind(&payload); err != nil {
		ctx.JSON(http.StatusBadRequest, map[string]string{core.KeyError: core.ErrInvalidRequest, core.KeyErrorDescription: err.Error()})
		return
	}
	if payload.Name == "" {
		ctx.JSON(http.StatusBadRequest, map[string]string{core.KeyError: core.ErrInvalidRequest})
		return
	}
	stored, err := store.Apply(ctx.Request().Context(), payload.toPolicy())
	if err != nil {
		d.SrvLogger().Error("netpolicy apply", "error", err)
		ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: core.ErrInternal})
		return
	}
	recordMutation(d, ctx, audit.EventNetPolicyApply, stored.Name)
	ctx.JSON(http.StatusOK, map[string]any{core.KeyNetPolicy: stored})
}

// HandleDelete implements DELETE /api/v1/netpolicy/policies/:name.
func HandleDelete(d HandlerDeps, ctx core.HandlerContext) {
	store := d.NetStore()
	if store == nil {
		ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: core.ErrNetPolicyNotConfigured})
		return
	}
	name := ctx.Param("name")
	if name == "" {
		ctx.JSON(http.StatusBadRequest, map[string]string{core.KeyError: core.ErrInvalidRequest})
		return
	}
	if err := store.Delete(ctx.Request().Context(), name); err != nil {
		d.SrvLogger().Error("netpolicy delete", "error", err)
		ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: core.ErrInternal})
		return
	}
	recordMutation(d, ctx, audit.EventNetPolicyDelete, name)
	ctx.JSON(http.StatusOK, map[string]string{core.KeyStatus: core.StatusOK})
}

// HandleClassify implements GET /api/v1/netpolicy/classify?remote_addr=&host=.
func HandleClassify(d HandlerDeps, ctx core.HandlerContext) {
	cls := d.NetClassifier()
	if cls == nil {
		ctx.JSON(http.StatusNotImplemented, map[string]string{core.KeyError: core.ErrNetPolicyNotConfigured})
		return
	}
	p := cls.Classify(ctx.Query("remote_addr"), ctx.Query("host"))
	if p == nil {
		ctx.JSON(http.StatusOK, map[string]any{core.KeyNetClass: ""})
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{core.KeyNetClass: p.Name, core.KeyNetPolicy: p})
}

// HandleResolveMe implements GET /api/v1/netpolicy/resolve-me.
// Classifies the CURRENT request and returns the matched policy.
func HandleResolveMe(d HandlerDeps, ctx core.HandlerContext) {
	cls := d.NetClassifier()
	if cls == nil {
		ctx.JSON(http.StatusNotImplemented, map[string]string{core.KeyError: core.ErrNetPolicyNotConfigured})
		return
	}
	r := ctx.Request()
	p := cls.Classify(r.RemoteAddr, r.Host)
	if p == nil {
		ctx.JSON(http.StatusOK, map[string]any{core.KeyNetClass: ""})
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{core.KeyNetClass: p.Name, core.KeyNetPolicy: p})
}

func recordMutation(d HandlerDeps, ctx core.HandlerContext, t audit.EventType, name string) {
	rec := d.Auditor()
	if rec == nil {
		return
	}
	r := ctx.Request()
	rec.Record(reqContext(r), &audit.Event{
		Type:      t,
		Outcome:   audit.OutcomeSuccess,
		Timestamp: time.Now().UTC(),
		ActorIP:   r.RemoteAddr,
		UserAgent: r.UserAgent(),
		Reason:    "name=" + name,
	})
}

// reqContext returns r.Context() but never nil — defensive against rare
// stdlib edge cases (custom transports etc.).
func reqContext(r *http.Request) context.Context {
	if r == nil {
		return context.Background()
	}
	if c := r.Context(); c != nil {
		return c
	}
	return context.Background()
}
