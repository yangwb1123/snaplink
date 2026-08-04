package txntoken_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/protocols/oauth/txntoken"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// testDeps is a real (not mocked) txntoken.Deps backed by the SAME
// Ed25519JWTIssuer the test mints ordinary access tokens with — mirrors
// protocols/oauth's own handler_harness_test.go convention: a functioning
// in-memory/real implementation, never a mock, of a small package-local
// interface with no existing SPI-catalog "Memory*" counterpart.
type testDeps struct {
	signer  *defaultimpl.Ed25519JWTIssuer
	issued  []string // clientID:strategy:subjectID per RecordTokenIssued call
	noopLog noopLogger
}

func (d *testDeps) ValidateAnyToken(ctx context.Context, token string) (*core.TokenClaims, string, error) {
	claims, err := d.signer.Validate(ctx, token)
	return claims, "jwt", err
}

func (d *testDeps) RecordTokenIssued(_ core.HandlerContext, clientID, strategy, subjectID string) {
	d.issued = append(d.issued, clientID+":"+strategy+":"+subjectID)
}

func (d *testDeps) SrvLogger() spi.Logger {
	return d.noopLog
}

type noopLogger struct{}

func (noopLogger) Info(string, ...any)  {}
func (noopLogger) Error(string, ...any) {}
func (noopLogger) Debug(string, ...any) {}

func newTestDeps(signer *defaultimpl.Ed25519JWTIssuer) *testDeps {
	return &testDeps{signer: signer}
}

// newGrantCtx builds a real *core.Context (no mock) backed by an
// httptest recorder, mirroring protocols/oauth's newCtx test helper.
func newGrantCtx() (*core.Context, *httptest.ResponseRecorder) {
	req := httptest.NewRequest("POST", "/token", strings.NewReader(""))
	rec := httptest.NewRecorder()
	return core.NewContext(rec, req), rec
}

func decodeGrantBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if rec.Body.Len() == 0 {
		return out
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response body %q: %v", rec.Body.String(), err)
	}
	return out
}

func TestHandleGrant_FirstHopFromAccessToken(t *testing.T) {
	signer, iss := newTestIssuer(t)
	validator := txntoken.NewValidator(signer, testTrustDomain)
	deps := newTestDeps(signer)

	tok, err := signer.Issue(context.Background(), &core.Subject{ID: "alice"}, []string{"orders:write"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	ctx, rec := newGrantCtx()
	client := &core.Client{ID: "checkout-svc"}
	txntoken.HandleGrant(deps, iss, validator, ctx, client, txntoken.Request{
		SubjectToken:     tok.AccessToken,
		SubjectTokenType: core.TokenTypeAccessToken,
		Audience:         []string{testTrustDomain},
		Purpose:          "order.create",
	})

	if rec.Code != 200 {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := decodeGrantBody(t, rec)
	if body[core.KeyIssuedTokenType] != txntoken.TokenType {
		t.Errorf("issued_token_type = %v, want %v", body[core.KeyIssuedTokenType], txntoken.TokenType)
	}
	signed, _ := body[core.KeyAccessToken].(string)
	if signed == "" {
		t.Fatal("expected a non-empty minted Txn-Token")
	}
	claims, err := validator.Validate(context.Background(), signed)
	if err != nil {
		t.Fatalf("Validate minted token: %v", err)
	}
	if claims.Sub != "alice" {
		t.Errorf("Sub = %q, want alice", claims.Sub)
	}
	if claims.Act == nil || claims.Act.Subject != "checkout-svc" {
		t.Errorf("Act = %+v, want outermost subject checkout-svc", claims.Act)
	}
	if len(deps.issued) != 1 {
		t.Errorf("RecordTokenIssued called %d times, want 1", len(deps.issued))
	}
}

func TestHandleGrant_NestedHopChains(t *testing.T) {
	signer, iss := newTestIssuer(t)
	validator := txntoken.NewValidator(signer, testTrustDomain)
	deps := newTestDeps(signer)

	firstSigned, firstClaims, err := iss.Mint(context.Background(), txntoken.MintRequest{
		Subject: "alice", RequestingWorkload: "checkout-svc", TrustDomain: testTrustDomain,
	})
	if err != nil {
		t.Fatalf("first Mint: %v", err)
	}

	ctx, rec := newGrantCtx()
	client := &core.Client{ID: "inventory-svc"}
	txntoken.HandleGrant(deps, iss, validator, ctx, client, txntoken.Request{
		SubjectToken:     firstSigned,
		SubjectTokenType: txntoken.TokenType,
		Audience:         []string{testTrustDomain},
	})
	if rec.Code != 200 {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := decodeGrantBody(t, rec)
	signed, _ := body[core.KeyAccessToken].(string)
	claims, err := validator.Validate(context.Background(), signed)
	if err != nil {
		t.Fatalf("Validate nested token: %v", err)
	}
	if claims.Sub != firstClaims.Sub {
		t.Errorf("nested Sub = %q, want unchanged %q", claims.Sub, firstClaims.Sub)
	}
	if claims.Act == nil || claims.Act.Subject != "inventory-svc" {
		t.Fatalf("nested Act = %+v, want outermost subject inventory-svc", claims.Act)
	}
	if claims.Act.Actor == nil || claims.Act.Actor.Subject != "checkout-svc" {
		t.Fatalf("nested Act.Actor = %+v, want nested subject checkout-svc", claims.Act.Actor)
	}
}

func TestHandleGrant_MissingSubjectTokenIsInvalidRequest(t *testing.T) {
	signer, iss := newTestIssuer(t)
	validator := txntoken.NewValidator(signer, testTrustDomain)
	deps := newTestDeps(signer)

	ctx, rec := newGrantCtx()
	txntoken.HandleGrant(deps, iss, validator, ctx, &core.Client{ID: "svc"}, txntoken.Request{
		Audience: []string{testTrustDomain},
	})
	assertErrorCode(t, rec, core.ErrInvalidRequest)
}

func TestHandleGrant_WrongAudienceIsInvalidTarget(t *testing.T) {
	signer, iss := newTestIssuer(t)
	validator := txntoken.NewValidator(signer, testTrustDomain)
	deps := newTestDeps(signer)

	tok, err := signer.Issue(context.Background(), &core.Subject{ID: "alice"}, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	ctx, rec := newGrantCtx()
	txntoken.HandleGrant(deps, iss, validator, ctx, &core.Client{ID: "svc"}, txntoken.Request{
		SubjectToken:     tok.AccessToken,
		SubjectTokenType: core.TokenTypeAccessToken,
		Audience:         []string{"not-the-trust-domain"},
	})
	assertErrorCode(t, rec, core.ErrInvalidTarget)
}

func TestHandleGrant_InvalidSubjectTokenIsInvalidGrant(t *testing.T) {
	signer, iss := newTestIssuer(t)
	validator := txntoken.NewValidator(signer, testTrustDomain)
	deps := newTestDeps(signer)

	ctx, rec := newGrantCtx()
	txntoken.HandleGrant(deps, iss, validator, ctx, &core.Client{ID: "svc"}, txntoken.Request{
		SubjectToken:     "not-a-real-token",
		SubjectTokenType: core.TokenTypeAccessToken,
		Audience:         []string{testTrustDomain},
	})
	assertErrorCode(t, rec, core.ErrInvalidGrant)
}

func TestHandleGrant_IDTokenDeclaredAsAccessTokenIsInvalidGrant(t *testing.T) {
	signer, iss := newTestIssuer(t)
	deps := newTestDeps(signer)
	idToken, err := signer.SignJWT(context.Background(), "JWT", map[string]any{
		"sub": "alice",
		"aud": "svc",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, rec := newGrantCtx()
	txntoken.HandleGrant(deps, iss, nil, ctx, &core.Client{ID: "svc"}, txntoken.Request{
		SubjectToken: idToken, SubjectTokenType: core.TokenTypeAccessToken,
		Audience: []string{testTrustDomain},
	})
	assertErrorCode(t, rec, core.ErrInvalidGrant)
}

func TestHandleGrant_MalformedRequestContextIsInvalidRequest(t *testing.T) {
	signer, iss := newTestIssuer(t)
	validator := txntoken.NewValidator(signer, testTrustDomain)
	deps := newTestDeps(signer)

	tok, err := signer.Issue(context.Background(), &core.Subject{ID: "alice"}, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	ctx, rec := newGrantCtx()
	txntoken.HandleGrant(deps, iss, validator, ctx, &core.Client{ID: "svc"}, txntoken.Request{
		SubjectToken:     tok.AccessToken,
		SubjectTokenType: core.TokenTypeAccessToken,
		Audience:         []string{testTrustDomain},
		RequestContext:   "{not json",
	})
	assertErrorCode(t, rec, core.ErrInvalidRequest)
}

func TestHandleGrant_NestedWithoutValidatorIsInvalidGrant(t *testing.T) {
	signer, iss := newTestIssuer(t)
	deps := newTestDeps(signer)

	firstSigned, _, err := iss.Mint(context.Background(), txntoken.MintRequest{
		Subject: "alice", TrustDomain: testTrustDomain,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	ctx, rec := newGrantCtx()
	// nil validator: nested minting must fail closed, not panic.
	txntoken.HandleGrant(deps, iss, nil, ctx, &core.Client{ID: "svc"}, txntoken.Request{
		SubjectToken:     firstSigned,
		SubjectTokenType: txntoken.TokenType,
		Audience:         []string{testTrustDomain},
	})
	assertErrorCode(t, rec, core.ErrInvalidGrant)
}

func assertErrorCode(t *testing.T, rec *httptest.ResponseRecorder, wantCode string) {
	t.Helper()
	if rec.Code < 400 {
		t.Fatalf("status = %d, want an error status; body = %s", rec.Code, rec.Body.String())
	}
	body := decodeGrantBody(t, rec)
	if got := body["error"]; got != wantCode {
		t.Errorf("error = %v, want %q (body %s)", got, wantCode, rec.Body.String())
	}
}
