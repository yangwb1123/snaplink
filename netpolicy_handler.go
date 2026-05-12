package sso

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/netpolicy"
)

// Response keys for netpolicy endpoints.
const (
	KeyNetPolicies = "policies"
	KeyNetClass    = "class"
	KeyNetPolicy   = "policy"
)

// JSON payload for POST /api/v1/netpolicy/policies. Mirrors the netpolicy.Policy
// fields callers are allowed to set — Version and UpdatedAt are server-stamped.
type netPolicyPayload struct {
	Name                string            `json:"name"`
	CIDRs               []string          `json:"cidrs,omitempty"`
	Hostnames           []string          `json:"hostnames,omitempty"`
	Priority            int32             `json:"priority,omitempty"`
	AdvertisedBaseURL   string            `json:"advertised_base_url,omitempty"`
	AdvertisedJWKSURL   string            `json:"advertised_jwks_url,omitempty"`
	AdvertisedLogoutURL string            `json:"advertised_logout_url,omitempty"`
	Metadata            map[string]string `json:"metadata,omitempty"`
}

func (p *netPolicyPayload) toPolicy() *netpolicy.Policy {
	return &netpolicy.Policy{
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

func (s *Server) handleListNetPolicies(ctx HandlerContext) {
	if s.netStore == nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrNetPolicyNotConfigured))
		return
	}
	policies, err := s.netStore.List(ctx.Request().Context())
	if err != nil {
		s.logger.Error("netpolicy list", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{KeyNetPolicies: policies})
}

func (s *Server) handleGetNetPolicy(ctx HandlerContext) {
	if s.netStore == nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrNetPolicyNotConfigured))
		return
	}
	name := ctx.Param("name")
	if name == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	p, err := s.netStore.Get(ctx.Request().Context(), name)
	if errors.Is(err, netpolicy.ErrNotFound) {
		ctx.JSON(http.StatusNotFound, errorBody(ErrNetPolicyNotFound))
		return
	}
	if err != nil {
		s.logger.Error("netpolicy get", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{KeyNetPolicy: p})
}

func (s *Server) handleApplyNetPolicy(ctx HandlerContext) {
	if s.netStore == nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrNetPolicyNotConfigured))
		return
	}
	var payload netPolicyPayload
	if err := ctx.Bind(&payload); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBodyWithDescription(ErrInvalidRequest, err.Error()))
		return
	}
	if payload.Name == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	stored, err := s.netStore.Apply(ctx.Request().Context(), payload.toPolicy())
	if err != nil {
		s.logger.Error("netpolicy apply", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	s.recordNetPolicyMutation(ctx, audit.EventNetPolicyApply, stored.Name)
	ctx.JSON(http.StatusOK, map[string]any{KeyNetPolicy: stored})
}

func (s *Server) handleDeleteNetPolicy(ctx HandlerContext) {
	if s.netStore == nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrNetPolicyNotConfigured))
		return
	}
	name := ctx.Param("name")
	if name == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	if err := s.netStore.Delete(ctx.Request().Context(), name); err != nil {
		s.logger.Error("netpolicy delete", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	s.recordNetPolicyMutation(ctx, audit.EventNetPolicyDelete, name)
	ctx.JSON(http.StatusOK, map[string]string{KeyStatus: StatusOK})
}

func (s *Server) handleClassifyNetPolicy(ctx HandlerContext) {
	if s.netClassifier == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(ErrNetPolicyNotConfigured))
		return
	}
	remoteAddr := ctx.Query("remote_addr")
	host := ctx.Query("host")
	p := s.netClassifier.Classify(remoteAddr, host)
	if p == nil {
		ctx.JSON(http.StatusOK, map[string]any{KeyNetClass: ""})
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{KeyNetClass: p.Name, KeyNetPolicy: p})
}

// handleResolveMeNetPolicy classifies the CURRENT request and returns the
// matched policy. Convenience endpoint for clients that want to discover
// "which JWKS URL / callback URL should I use" without re-implementing the
// classification.
func (s *Server) handleResolveMeNetPolicy(ctx HandlerContext) {
	if s.netClassifier == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(ErrNetPolicyNotConfigured))
		return
	}
	r := ctx.Request()
	remoteAddr := r.RemoteAddr
	host := r.Host
	p := s.netClassifier.Classify(remoteAddr, host)
	if p == nil {
		ctx.JSON(http.StatusOK, map[string]any{KeyNetClass: ""})
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{KeyNetClass: p.Name, KeyNetPolicy: p})
}

// ClassifyRequest is exposed for embedders that want to classify a request
// in their own middleware. Returns nil when no classifier is wired or no
// policy matches.
func (s *Server) ClassifyRequest(r *http.Request) *netpolicy.Policy {
	if s.netClassifier == nil || r == nil {
		return nil
	}
	return s.netClassifier.Classify(r.RemoteAddr, r.Host)
}

func (s *Server) recordNetPolicyMutation(ctx HandlerContext, t audit.EventType, name string) {
	if s.auditor == nil {
		return
	}
	r := ctx.Request()
	s.auditor.Record(reqContext(r), &audit.Event{
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
	if ctx := r.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}
