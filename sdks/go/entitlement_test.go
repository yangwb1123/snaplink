package snaplink

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The cases in ops/build/sdk-conformance/entitlement.json are the shared
// contract, so a change to the fixture changes what every SDK is held to. The
// fixture stores Unix seconds and string-keyed maps to stay readable from any
// language; NewEntitlement is the only place that mapping happens.

const referenceNow int64 = 1_700_000_000

type entitlementCase struct {
	ID                   string                `json:"id"`
	Now                  *int64                `json:"now"`
	Entitlement          map[string]any        `json:"entitlement"`
	ExpectState          string                `json:"expect_state"`
	ExpectInactiveReason string                `json:"expect_inactive_reason"`
	ExpectFeatures       map[string]bool       `json:"expect_features"`
	ExpectLimits         map[string]LimitGrant `json:"expect_limits"`
}

type entitlementFixture struct {
	Cases []entitlementCase `json:"cases"`
}

func loadFixture(t *testing.T) entitlementFixture {
	t.Helper()
	path := filepath.Join("..", "..", "ops", "build", "sdk-conformance", "entitlement.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read the shared fixture: %v", err)
	}
	var fixture entitlementFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("the shared fixture must be valid JSON: %v", err)
	}
	if len(fixture.Cases) == 0 {
		t.Fatal("the shared fixture must not be empty")
	}
	return fixture
}

func fixtureContext(t *testing.T, testCase entitlementCase) AccountContext {
	t.Helper()
	context := AccountContext{ProductID: "product-a", TenantID: "tenant-a"}
	if testCase.Entitlement != nil {
		context.Entitlement = testCase.Entitlement
	}
	return context
}

func caseTime(testCase entitlementCase) time.Time {
	if testCase.Now != nil {
		return time.Unix(*testCase.Now, 0).UTC()
	}
	return time.Unix(referenceNow, 0).UTC()
}

func TestFixtureIsReachableAndPopulated(t *testing.T) {
	loadFixture(t)
}

func TestEveryCaseClassifiesAsTheContractRequires(t *testing.T) {
	for _, testCase := range loadFixture(t).Cases {
		t.Run(testCase.ID, func(t *testing.T) {
			state := fixtureContext(t, testCase).License(caseTime(testCase))
			if string(state.Kind) != testCase.ExpectState {
				t.Fatalf("classified as %s, want %s", state.Kind, testCase.ExpectState)
			}
			if testCase.ExpectInactiveReason != "" {
				if string(state.Reason) != testCase.ExpectInactiveReason {
					t.Fatalf("reason %s, want %s", state.Reason, testCase.ExpectInactiveReason)
				}
			}
		})
	}
}

func TestAPresentEntitlementIsNotNecessarilyEffective(t *testing.T) {
	for _, testCase := range loadFixture(t).Cases {
		t.Run(testCase.ID, func(t *testing.T) {
			context := fixtureContext(t, testCase)
			entitlement, err := context.TypedEntitlement()
			present := err == nil && entitlement != nil
			grants := context.License(caseTime(testCase)).Active()
			if present && !grants && LicenseStateKind(testCase.ExpectState) == StateActive {
				t.Fatal("granted while the contract says otherwise")
			}
		})
	}
}

func TestTheExpiryBoundaryIsExclusive(t *testing.T) {
	for _, testCase := range loadFixture(t).Cases {
		if testCase.ID != "exactly_at_expiry" {
			continue
		}
		context := fixtureContext(t, testCase)
		expiresAt := time.Unix(1_800_000_000, 0).UTC()
		if !context.License(expiresAt.Add(-time.Second)).Active() {
			t.Fatal("one second before expiry must still grant")
		}
		if context.License(expiresAt).Active() {
			t.Fatal("the expiry second itself must not grant")
		}
		return
	}
	t.Fatal("the boundary case must exist")
}

func TestFeatureLookupsMatchTheContract(t *testing.T) {
	for _, testCase := range loadFixture(t).Cases {
		for key, want := range testCase.ExpectFeatures {
			t.Run(testCase.ID+"/"+key, func(t *testing.T) {
				got := fixtureContext(t, testCase).HasFeature(Feature(key), caseTime(testCase))
				if got != want {
					t.Fatalf("HasFeature(%s) = %v, want %v", key, got, want)
				}
			})
		}
	}
}

func TestLimitLookupsMatchTheContract(t *testing.T) {
	for _, testCase := range loadFixture(t).Cases {
		for key, want := range testCase.ExpectLimits {
			t.Run(testCase.ID+"/"+key, func(t *testing.T) {
				context := fixtureContext(t, testCase)
				entitlement, err := context.TypedEntitlement()
				if err != nil || entitlement == nil {
					t.Fatalf("cannot build the entitlement: %v", err)
				}
				grant, ok := entitlement.Limit(Limit(key), caseTime(testCase))
				if !ok {
					if context.License(caseTime(testCase)).Active() {
						t.Fatalf("lost an active limit %s", key)
					}
					return
				}
				if grant.Soft != want.Soft || grant.Hard != want.Hard || grant.Unlimited != want.Unlimited {
					t.Fatalf("limit %s = %+v, want %+v", key, grant, want)
				}
			})
		}
	}
}

func TestAnAbsentEntitlementIsNeverUnlimited(t *testing.T) {
	context := AccountContext{ProductID: "p", TenantID: "t"}
	state := context.License(time.Unix(referenceNow, 0))
	if state.Kind != StateNotActivated {
		t.Fatalf("kind %s, want %s", state.Kind, StateNotActivated)
	}
	if context.HasFeature(FeatureCoreSSO, time.Unix(referenceNow, 0)) {
		t.Fatal("an absent entitlement must grant nothing")
	}
}

func TestEveryDefinedKeyExists(t *testing.T) {
	if len(AllFeatures()) != 10 {
		t.Fatalf("the server defines ten feature keys, got %d", len(AllFeatures()))
	}
	if len(AllLimits()) != 6 {
		t.Fatalf("the server defines six limit keys, got %d", len(AllLimits()))
	}
}

func TestRFC3339AndUnixSecondsParseIdentically(t *testing.T) {
	raw := []byte(`{"active":true,"features":{},"limits":{},
		"effective_at":"2023-11-14T22:13:19Z","expires_at":"2023-11-14T22:13:20Z"}`)
	fromString, err := NewEntitlement(raw)
	if err != nil {
		t.Fatalf("RFC 3339 must parse: %v", err)
	}
	numeric, err := NewEntitlement([]byte(`{"active":true,"features":{},"limits":{},
		"effective_at":1699999999,"expires_at":1700000000}`))
	if err != nil {
		t.Fatalf("Unix seconds must parse: %v", err)
	}
	if !fromString.EffectiveAt.Equal(numeric.EffectiveAt) || !fromString.ExpiresAt.Equal(numeric.ExpiresAt) {
		t.Fatal("both forms must land on the same instant")
	}
	now := time.Unix(referenceNow, 0).UTC()
	if fromString.StateAt(now) != numeric.StateAt(now) {
		t.Fatal("both forms must classify identically")
	}
}

func TestAnUnparseableTimestampIsRejected(t *testing.T) {
	if _, err := NewEntitlement([]byte(`{"effective_at":"not-a-timestamp"}`)); err == nil {
		t.Fatal("a malformed timestamp must not silently become zero")
	}
}

func TestAnUnrecognisedKeyIsPreservedButGrantsNothing(t *testing.T) {
	entitlement, err := NewEntitlement([]byte(`{"active":true,
		"effective_at":1600000000,
		"features":{"core_sso":true,"telemetry_magic":true},"limits":{}}`))
	if err != nil {
		t.Fatalf("an unknown key must not fail the parse: %v", err)
	}
	unknown := entitlement.UnknownFeatures()
	if len(unknown) != 1 || unknown[0] != "telemetry_magic" {
		t.Fatalf("the unknown key must be visible, got %v", unknown)
	}
	now := time.Unix(referenceNow, 0).UTC()
	if !entitlement.Has(FeatureCoreSSO, now) {
		t.Fatal("known keys still resolve")
	}
	if entitlement.Has(Feature("telemetry_magic"), now) {
		t.Fatal("an unknown key must not grant")
	}
}
