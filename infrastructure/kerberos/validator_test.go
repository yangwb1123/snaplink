package kerberosauth

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/test/testdata"
)

// realKeytabConfig builds a Config backed by gokrb5's OWN test keytab fixture
// (HTTP/host.test.gokrb5@TEST.GOKRB5). This is a REAL keytab — no fake — so it
// exercises the production NewGokrb5Validator + gokrb5Validator.Validate paths.
// It is time-INDEPENDENT and KDC-free: we never present a valid live ticket
// (which would require a running KDC and would be a date-bomb as the ticket
// expires), only forged/garbage tokens, so the test proves the security
// contract — the real validator FAILS CLOSED — without any clock or network
// dependency.
func realKeytabConfig(t *testing.T) Config {
	t.Helper()
	ktBytes, err := hex.DecodeString(testdata.HTTP_KEYTAB)
	if err != nil {
		t.Fatalf("decode test keytab: %v", err)
	}
	return Config{
		Name:             "kerberos",
		KeytabBytes:      ktBytes,
		ServicePrincipal: "HTTP/host.test.gokrb5",
		Realm:            "TEST.GOKRB5",
		ClientID:         "kiosk-app",
	}
}

// TestGokrb5Validator_ConstructsFromKeytab proves the production validator
// loads a real keytab at construction (no KDC, no network) — the operator's
// boot path.
func TestGokrb5Validator_ConstructsFromKeytab(t *testing.T) {
	t.Parallel()
	v, err := NewGokrb5Validator(realKeytabConfig(t))
	if err != nil {
		t.Fatalf("NewGokrb5Validator with a real keytab: %v", err)
	}
	if v == nil || v.svc == nil {
		t.Fatal("validator or its SPNEGO service is nil")
	}
}

// TestGokrb5Validator_FailsClosed is the SECURITY contract on the REAL
// validator: forged / empty / non-SPNEGO / truncated tokens ALL fail closed
// (non-nil error, no principal). A forged SPNEGO token can NEVER authenticate
// against the keytab. Time-independent (none of these are valid tickets).
func TestGokrb5Validator_FailsClosed(t *testing.T) {
	t.Parallel()
	v, err := NewGokrb5Validator(realKeytabConfig(t))
	if err != nil {
		t.Fatalf("NewGokrb5Validator: %v", err)
	}

	// A real (well-formed) SPNEGO NegTokenInit captured from gokrb5's own test
	// vectors — but it is NOT a ticket minted for THIS keytab's key in a live
	// window, so validating it against the keytab MUST fail (bad signature /
	// expired / wrong key). This is the closest a forged-but-structurally-valid
	// token gets, and it must still be rejected.
	realStructuredToken, decErr := hex.DecodeString(spnegoInitVector)
	if decErr != nil {
		t.Fatalf("decode spnego vector: %v", decErr)
	}

	cases := []struct {
		name  string
		token []byte
	}{
		{"empty", nil},
		{"garbage", []byte("definitely-not-a-spnego-token")},
		{"truncated", []byte{0x60, 0x82}},
		{"structurally-valid-but-not-for-this-keytab", realStructuredToken},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			principal, realm, groups, err := v.Validate(context.Background(), tc.token)
			if err == nil {
				t.Fatalf("Validate(%s) returned nil error — a non-authenticating token MUST fail closed", tc.name)
			}
			if principal != "" || realm != "" || groups != nil {
				t.Errorf("Validate(%s) leaked identity on failure: principal=%q realm=%q groups=%v", tc.name, principal, realm, groups)
			}
			// Every failure collapses to ErrValidate (the oracle-safe class) —
			// the handler maps it to one generic 401.
			if !strings.Contains(err.Error(), "validation failed") {
				t.Errorf("Validate(%s) error = %q, want it to wrap ErrValidate", tc.name, err)
			}
		})
	}
}

// TestNewGokrb5Validator_BadKeytab proves a malformed keytab fails construction
// CLOSED (the operator's boot fails loud) and that the error carries NO keytab
// bytes.
func TestNewGokrb5Validator_BadKeytab(t *testing.T) {
	t.Parallel()
	cfg := realKeytabConfig(t)
	cfg.KeytabBytes = []byte("not-a-keytab")
	_, err := NewGokrb5Validator(cfg)
	if err == nil {
		t.Fatal("NewGokrb5Validator with a malformed keytab should error")
	}
	if !strings.Contains(err.Error(), "load keytab") {
		t.Errorf("err = %v, want a load-keytab error", err)
	}
	if strings.Contains(err.Error(), "not-a-keytab") {
		t.Error("error leaked the keytab bytes")
	}
}

// TestNewGokrb5Validator_RejectsBadConfig proves construction runs Config
// validation (a missing keytab / realm / client_id fails here, before any
// keytab load).
func TestNewGokrb5Validator_RejectsBadConfig(t *testing.T) {
	t.Parallel()
	if _, err := NewGokrb5Validator(Config{Name: "k"}); err == nil {
		t.Error("NewGokrb5Validator with an empty config should error")
	}
}

// settingsSkew applies the Config's serviceOpts to a fresh service.Settings and
// returns the resulting MaxClockSkew. gokrb5's getter returns its 5-minute
// default when the option was never set, so this distinguishes "knob unset"
// (== default) from "knob plumbed" (== the configured value).
func settingsSkew(cfg Config) time.Duration {
	s := service.NewSettings(nil, serviceOpts(cfg)...)
	return s.MaxClockSkew()
}

// TestMaxClockSkew_Plumbing (FIX #5) proves the optional skew knob: ZERO leaves
// gokrb5's 5-minute default UNCHANGED (no MaxClockSkew option is added — the
// opts are byte-identical to before the knob existed), while a NON-ZERO value
// plumbs through to service.MaxClockSkew so the validator enforces the
// operator's window.
func TestMaxClockSkew_Plumbing(t *testing.T) {
	t.Parallel()
	const gokrb5Default = 5 * time.Minute

	cfg := realKeytabConfig(t)
	// (a) Zero ⇒ gokrb5 default, i.e. exactly what the pre-knob build produced.
	if cfg.MaxClockSkew != 0 {
		t.Fatalf("precondition: realKeytabConfig should have zero skew, got %v", cfg.MaxClockSkew)
	}
	if got := settingsSkew(cfg); got != gokrb5Default {
		t.Errorf("zero MaxClockSkew settings = %v, want gokrb5 default %v (byte-identical to no option)", got, gokrb5Default)
	}

	// (b) A non-zero override is plumbed through verbatim.
	cfg.MaxClockSkew = 30 * time.Second
	if got := settingsSkew(cfg); got != 30*time.Second {
		t.Errorf("MaxClockSkew=30s settings = %v, want 30s (the option was not plumbed)", got)
	}

	// (c) The option count grows by exactly one when set (proves we APPEND a
	// MaxClockSkew opt rather than mutate the existing ones).
	zero := realKeytabConfig(t)
	set := realKeytabConfig(t)
	set.MaxClockSkew = time.Minute
	if n0, n1 := len(serviceOpts(zero)), len(serviceOpts(set)); n1 != n0+1 {
		t.Errorf("serviceOpts len: zero=%d set=%d, want set==zero+1", n0, n1)
	}

	// (d) A validator constructed with the override builds cleanly (the opt is
	// accepted by gokrb5 end-to-end).
	if _, err := NewGokrb5Validator(set); err != nil {
		t.Errorf("NewGokrb5Validator with MaxClockSkew set: %v", err)
	}
}

// TestGokrb5ReplayCache_IsFirstCallerSingleton pins, against the REAL gokrb5
// library (not its godoc), the exact claim the Config.MaxClockSkew and
// gokrb5Validator.svc comments make: service.GetReplayCache is a sync.Once
// package-level singleton — the FIRST call's duration argument wins for the
// lifetime of the PROCESS; a later call with a DIFFERENT duration returns the
// identical cache, not a new one sized to the new duration. This is why this
// module's Config.MaxClockSkew only reliably governs replay-cache retention
// for the first Kerberos surface built in a process; a naive reading of the
// gokrb5 godoc alone would suggest each call's duration takes effect, which is
// false. A pointer-identity check is the simplest proof that no new Cache was
// constructed for the second, differently-configured call.
func TestGokrb5ReplayCache_IsFirstCallerSingleton(t *testing.T) {
	first := service.GetReplayCache(5 * time.Minute)
	second := service.GetReplayCache(10 * time.Second)
	if first != second {
		t.Fatalf("service.GetReplayCache returned distinct instances (%p vs %p) for two different durations — expected the SAME sync.Once-guarded singleton regardless of the argument, proving retention is fixed by the FIRST caller in the process", first, second)
	}
}

// TestExtractGroups_HappyPath (FIX #1) is a focused proof that the dead JSON
// fallback removal did not change happy-path group extraction: a credentials
// value carrying AD group SIDs still yields them, and one with none yields nil.
// (The real-keytab FailsClosed test already proves the production decode path;
// this pins the helper's contract directly without a KDC.)
func TestExtractGroups_HappyPath(t *testing.T) {
	t.Parallel()
	// No PAC / no AD creds ⇒ nil (enrichment, not a gate). credentials.New
	// initializes the internal attribute maps (new(Credentials) would not).
	empty := credentials.New("svc", "TEST.GOKRB5")
	if got := extractGroups(empty); got != nil {
		t.Errorf("extractGroups(no PAC) = %v, want nil", got)
	}

	// AD creds with group SIDs ⇒ those SIDs, copied out — the value-typed
	// ADCredentials path gokrb5 actually produces (the only path now that the
	// dead JSON-string fallback is gone).
	withGroups := credentials.New("alice", "TEST.GOKRB5")
	withGroups.SetADCredentials(credentials.ADCredentials{
		GroupMembershipSIDs: []string{"S-1-5-21-aaa", "S-1-5-21-bbb"},
	})
	got := extractGroups(withGroups)
	if len(got) != 2 || got[0] != "S-1-5-21-aaa" || got[1] != "S-1-5-21-bbb" {
		t.Errorf("extractGroups(with PAC) = %v, want the two SIDs", got)
	}
}

// spnegoInitVector is a well-formed SPNEGO NegTokenInit lifted verbatim from
// gokrb5's own spnego test vectors (spnego_test.go testGSSAPIInit). It parses
// as a valid SPNEGO token but is NOT a live ticket for our keytab, so the
// validator must reject it (proving structure alone never authenticates).
const spnegoInitVector = "608202b606062b0601050502a08202aa308202a6a027302506092a864886f71201020206052b0501050206092a864882f71201020206062b0601050205a2820279048202756082027106092a864886f71201020201006e8202603082025ca003020105a10302010ea20703050000000000a38201706182016c30820168a003020105a10d1b0b544553542e474f4b524235a2233021a003020103a11a30181b04485454501b10686f73742e746573742e676f6b726235a382012b30820127a003020112a103020102a282011904820115d4bd890abc456f44e2e7a2e8111bd6767abf03266dfcda97c629af2ece450a5ae1f145e4a4d1bc2c848e66a6c6b31d9740b26b03cdbd2570bfcf126e90adf5f5ebce9e283ff5086da47b129b14fc0aabd4d1df9c1f3c72b80cc614dfc28783450b2c7b7749651f432b47aaa2ff158c0066b757f3fb00dd7b4f63d68276c76373ecdd3f19c66ebc43a81e577f3c263b878356f57e8d6c4eccd587b81538e70392cf7e73fc12a6f7c537a894a7bb5566c83ac4d69757aa320a51d8d690017aebf952add1889adfc3307b0e6cd8c9b57cf8589fbe52800acb6461c25473d49faa1bdceb8bce3f61db23f9cd6a09d5adceb411e1c4546b30b33331e570fd6bc50aa403557e75f488e759750ea038aab6454667d9b64f41a481d23081cfa003020112a281c70481c4eb593beb5afcb1a2a669d54cb85a3772231559f2d40c9f8f053f218ba6eb084ed7efc467d94b88bcd189dda920d6e675ec001a6a2bca11f0a1de37f2f7ae9929f94a86d625b2ec1b213a88cbae6099dda7b172cd3bd1802cb177ae4554d59277004bfd3435248f55044fe7af7b2c9c5a3c43763278c585395aebe2856cdff9f2569d8b823564ce6be2d19748b910ec06bd3c0a9bc5de51ddcf7d875f1108ca6ad935f52d90cb62a18197d9b8e796bef0fbe1463f61df61cfbce6008ae9e1a2d2314a986d"
