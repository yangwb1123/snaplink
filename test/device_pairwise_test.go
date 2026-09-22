package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/security"
)

const (
	devicePairwiseUser     = "device-pairwise-user"
	devicePairwiseBrowser  = "device-pairwise-browser"
	devicePairwiseCLI      = "device-pairwise-cli"
	devicePairwiseSector   = "https://shared.example.test/sector.json"
	devicePairwiseResource = "device-pairwise-api"
)

type devicePairwiseHarness struct {
	server  *httptest.Server
	issuer  *defaultimpl.Ed25519JWTIssuer
	devices oauth.DeviceCodeStore
}

func newDevicePairwiseHarness(t *testing.T, approverType, deviceType, deviceSector string, pairs security.PairwiseSubjectStore) devicePairwiseHarness {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	if err := users.CreateOrUpdate(context.Background(), &sso.User{ID: devicePairwiseUser}); err != nil {
		t.Fatal(err)
	}
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(devicePairwiseClient(devicePairwiseBrowser, approverType, devicePairwiseSector))
	clients.AddSeed(devicePairwiseClient(devicePairwiseCLI, deviceType, deviceSector))
	issuer := defaultimpl.NewEd25519JWTIssuer()
	devices := defaultimpl.NewMemoryDeviceCodeStore()
	server := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(stubPasswordAuth{userID: devicePairwiseUser}),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPairwiseSubjectStore(pairs),
		sso.WithPairwiseSalt("device-pairwise-test-salt"),
		sso.WithDeviceCodeStore(devices, time.Minute, time.Nanosecond, ""),
	)
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)
	return devicePairwiseHarness{server: httpServer, issuer: issuer, devices: devices}
}

func devicePairwiseClient(id, subjectType, sector string) *sso.Client {
	return &sso.Client{
		ID: id, Active: true, TokenStrategy: "jwt", TokenEndpointAuthMethod: "none",
		SubjectType: subjectType, SectorIdentifierURI: sector, TenantID: "device-pairwise-tenant",
		AllowedAuthenticators: []string{"password"}, AllowedScopes: []string{"openid"},
		AllowedResources: []string{devicePairwiseResource}, GrantTypes: []string{sso.GrantDeviceCode},
	}
}

func devicePairwiseLogin(t *testing.T, h devicePairwiseHarness, clientID string) string {
	t.Helper()
	status, body := postJSON(t, h.server, "/auth/login", map[string]any{
		"provider": "password", "client_id": clientID,
		"credential": map[string]string{"username": "fixture", "password": "fixture"},
		"scope":      []string{"openid"}, "resource": []string{devicePairwiseResource},
	})
	if status != http.StatusOK {
		t.Fatalf("login status = %d, body = %v", status, body)
	}
	return devicePairwiseAccessToken(t, body)
}

func devicePairwiseAccessToken(t *testing.T, body map[string]any) string {
	t.Helper()
	token, _ := body["access_token"].(string)
	if token == "" {
		t.Fatal("response omitted access token")
	}
	return token
}

func devicePairwiseStart(t *testing.T, h devicePairwiseHarness) (string, string) {
	t.Helper()
	status, body := postJSON(t, h.server, "/device/code", map[string]any{
		"client_id": devicePairwiseCLI, "scope": "openid", "resource": []string{devicePairwiseResource},
	})
	if status != http.StatusOK {
		t.Fatalf("device start status = %d, body = %v", status, body)
	}
	deviceCode, _ := body["device_code"].(string)
	userCode, _ := body["user_code"].(string)
	if deviceCode == "" || userCode == "" {
		t.Fatal("device start omitted codes")
	}
	return deviceCode, userCode
}

func devicePairwiseDecision(t *testing.T, h devicePairwiseHarness, bearer, userCode string) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"user_code": userCode, "approve": true})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, h.server.URL+"/device/verify", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body
}

func devicePairwisePoll(t *testing.T, h devicePairwiseHarness, code string) (int, map[string]any) {
	t.Helper()
	return postJSON(t, h.server, "/token", map[string]any{
		"grant_type": sso.GrantDeviceCode, "client_id": devicePairwiseCLI, "device_code": code,
	})
}

func TestDevice_PairwiseApprovalPreservesClientSubject(t *testing.T) {
	for _, tc := range []struct{ name, approverType, deviceType, sector string }{
		{"public_to_public", security.SubjectTypePublic, security.SubjectTypePublic, devicePairwiseSector},
		{"public_to_pairwise", security.SubjectTypePublic, security.SubjectTypePairwise, devicePairwiseSector},
		{"pairwise_same_sector", security.SubjectTypePairwise, security.SubjectTypePairwise, devicePairwiseSector},
		{"pairwise_other_sector", security.SubjectTypePairwise, security.SubjectTypePairwise, "https://other.example.test/sector.json"},
		{"pairwise_to_public", security.SubjectTypePairwise, security.SubjectTypePublic, devicePairwiseSector},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newDevicePairwiseHarness(t, tc.approverType, tc.deviceType, tc.sector, security.NewMemoryPairwiseSubjectStore())
			approver := devicePairwiseLogin(t, h, devicePairwiseBrowser)
			direct := devicePairwiseLogin(t, h, devicePairwiseCLI)
			code, userCode := devicePairwiseStart(t, h)
			if status, body := devicePairwiseDecision(t, h, approver, userCode); status != http.StatusOK {
				t.Fatalf("approval status = %d, body = %v", status, body)
			}
			status, body := devicePairwisePoll(t, h, code)
			if status != http.StatusOK {
				t.Fatalf("device poll status = %d, body = %v", status, body)
			}
			assertDevicePairwiseIdentity(t, h, direct, devicePairwiseAccessToken(t, body))
		})
	}
}

func assertDevicePairwiseIdentity(t *testing.T, h devicePairwiseHarness, direct, device string) {
	t.Helper()
	directClaims, err := h.issuer.Validate(context.Background(), direct)
	if err != nil {
		t.Fatal(err)
	}
	deviceClaims, err := h.issuer.Validate(context.Background(), device)
	if err != nil {
		t.Fatal(err)
	}
	if deviceClaims.Subject != directClaims.Subject {
		t.Errorf("device subject = %q, direct login subject = %q", deviceClaims.Subject, directClaims.Subject)
	}
	if deviceClaims.ClientID != devicePairwiseCLI || deviceClaims.TenantID != directClaims.TenantID {
		t.Error("device token changed the target client's identity binding")
	}
	userinfo := fetchUserInfo(t, h.server, device)
	if userinfo["sub"] != directClaims.Subject {
		t.Errorf("userinfo sub = %v, want direct login subject %q", userinfo["sub"], directClaims.Subject)
	}
}

type devicePairwiseFailingStore struct {
	security.PairwiseSubjectStore
	fail atomic.Bool
}

func (s *devicePairwiseFailingStore) LocalSubject(ctx context.Context, sub string) (string, error) {
	if s.fail.Load() {
		return "", errors.New("pairwise store unavailable")
	}
	return s.PairwiseSubjectStore.LocalSubject(ctx, sub)
}

func TestDevice_PairwiseResolutionFailureDoesNotApprove(t *testing.T) {
	pairs := &devicePairwiseFailingStore{PairwiseSubjectStore: security.NewMemoryPairwiseSubjectStore()}
	h := newDevicePairwiseHarness(t, security.SubjectTypePairwise, security.SubjectTypePairwise, devicePairwiseSector, pairs)
	approver := devicePairwiseLogin(t, h, devicePairwiseBrowser)
	code, userCode := devicePairwiseStart(t, h)
	pairs.fail.Store(true)
	status, body := devicePairwiseDecision(t, h, approver, userCode)
	if status != http.StatusUnauthorized || body["error"] != "invalid_token" {
		t.Errorf("approval status = %d, body = %v; want 401 invalid_token", status, body)
	}
	stored, err := h.devices.GetByDeviceCode(context.Background(), code)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Approved || stored.Denied || stored.UserID != "" {
		t.Error("failed subject resolution changed the pending device grant")
	}
	status, body = devicePairwisePoll(t, h, code)
	if status != http.StatusBadRequest || body["error"] != "authorization_pending" {
		t.Errorf("poll after failed approval = %d %v; want authorization_pending", status, body)
	}
	pairs.fail.Store(false)
	if status, body := devicePairwiseDecision(t, h, approver, userCode); status != http.StatusOK {
		t.Fatalf("approval after store recovery = %d %v", status, body)
	}
}
