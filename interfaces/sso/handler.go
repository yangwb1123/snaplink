package sso

import (
	"net/http"

	"github.com/snaplink/sso/domains/tenant"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
)

// errorBody delegates to core/error_body.go. Keep the lowercase name so the
// 100+ call sites stay one-line.
func errorBody(code string) map[string]string { return core.ErrorBody(code) }

// bearerToken delegates to oauth.BearerToken — see that function for
// the RFC 6750 §2.1 missing-vs-bad-credential distinction.
func bearerToken(r *http.Request) string { return oauth.BearerToken(r) }

// clientTenantOK delegates to tenant.ClientOK.
func clientTenantOK(ctx HandlerContext, client *Client) bool {
	return tenant.ClientOK(ctx, client)
}

func (s *Server) handleHealth(ctx HandlerContext) {
	bi := ReadBuildInfo()
	resp := map[string]string{
		KeyStatus:  StatusOK,
		KeyIssuer:  s.issuer,
		KeyVersion: bi.Version,
	}
	if bi.VCSRevision != "" {
		resp[KeyVCSRevision] = bi.VCSRevision
	}
	if bi.VCSTime != "" {
		resp[KeyVCSTime] = bi.VCSTime
	}
	ctx.JSON(http.StatusOK, resp)
}
