package securityverify

import (
	"strings"
	"testing"
)

func TestIsJARFetchableURI(t *testing.T) {
	t.Parallel()

	tests := []struct {
		uri  string
		want bool
	}{
		{"https://example.com/jar", true},
		{"http://example.com/jar", false},
		{"file:///tmp/jar", false},
		{"", false},
		{"HTTPS://example.com/jar", false},
		{"urn:ietf:params:oauth:jwk", false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.uri, func(t *testing.T) {
			t.Parallel()
			got := IsJARFetchableURI(tc.uri)
			if got != tc.want {
				t.Errorf("IsJARFetchableURI(%q) = %v, want %v", tc.uri, got, tc.want)
			}
		})
	}
}

func TestIsRequestURIAllowed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		uri     string
		allowed []string
		want    bool
	}{
		{"https://example.com/jar", []string{"https://example.com/jar"}, true},
		{"https://example.com/jar", []string{"https://other.com/jar"}, false},
		{"https://example.com/jar", nil, false},
		{"https://example.com/jar", []string{}, false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.uri, func(t *testing.T) {
			t.Parallel()
			got := IsRequestURIAllowed(tc.uri, tc.allowed)
			if got != tc.want {
				t.Errorf("IsRequestURIAllowed(%q, %v) = %v, want %v", tc.uri, tc.allowed, got, tc.want)
			}
		})
	}
}

func TestQuoteAuthParam(t *testing.T) {
	t.Parallel()

	tests := []struct {
		v    string
		want string
	}{
		{"", `""`},
		{"hello", `"hello"`},
		{`he"llo`, `"he\"llo"`},
		{`he\llo`, `"he\\llo"`},
		{`a"b\c"d`, `"a\"b\\c\"d"`},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.v, func(t *testing.T) {
			t.Parallel()
			got := QuoteAuthParam(tc.v)
			if got != tc.want {
				t.Errorf("QuoteAuthParam(%q) = %q, want %q", tc.v, got, tc.want)
			}
		})
	}
}

func TestParseK8sWorkloadPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path   string
		wantNS string
		wantSA string
	}{
		{path: "ns/default/sa/my-service", wantNS: "default", wantSA: "my-service"},
		{path: "ns/kube-system/sa/controller", wantNS: "kube-system", wantSA: "controller"},
		{path: "/other/path", wantNS: "", wantSA: ""},
		{path: "/ns/only/sa/missing/extra", wantNS: "", wantSA: ""},
		{path: "", wantNS: "", wantSA: ""},
		{path: "/ns/default", wantNS: "", wantSA: ""},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			ns, sa := parseK8sWorkloadPath(tc.path)
			if ns != tc.wantNS || sa != tc.wantSA {
				t.Errorf("parseK8sWorkloadPath(%q) = (%q, %q), want (%q, %q)", tc.path, ns, sa, tc.wantNS, tc.wantSA)
			}
		})
	}
}

func TestAsymmetricJWSAlgs(t *testing.T) {
	t.Parallel()

	algs := AsymmetricJWSAlgs()
	if len(algs) == 0 {
		t.Fatal("AsymmetricJWSAlgs() returned empty map")
	}
	// EdDSA should be included
	if _, ok := algs[jwsAlgEdDSA]; !ok {
		t.Error("AsymmetricJWSAlgs() missing EdDSA")
	}
	// RS256 should be included
	if _, ok := algs[jwsAlgRS256]; !ok {
		t.Error("AsymmetricJWSAlgs() missing RS256")
	}
	// None should NOT be included
	if _, ok := algs["none"]; ok {
		t.Error("AsymmetricJWSAlgs() should not include 'none'")
	}
}

func TestAsymmetricJWSAlgValues(t *testing.T) {
	t.Parallel()

	values := AsymmetricJWSAlgValues()
	if len(values) == 0 {
		t.Fatal("AsymmetricJWSAlgValues() returned empty slice")
	}
	// Should be sorted
	for i := 1; i < len(values); i++ {
		if values[i-1] > values[i] {
			t.Errorf("AsymmetricJWSAlgValues() not sorted: %v", values)
			break
		}
	}
}

func TestIsAsymmetricJWSAlg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		alg  string
		want bool
	}{
		{jwsAlgEdDSA, true},
		{jwsAlgES256, true},
		{jwsAlgES384, true},
		{jwsAlgES512, true},
		{jwsAlgRS256, true},
		{jwsAlgPS256, true},
		{"none", false},
		{"HS256", false},
		{"", false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.alg, func(t *testing.T) {
			t.Parallel()
			got := isAsymmetricJWSAlg(tc.alg)
			if got != tc.want {
				t.Errorf("isAsymmetricJWSAlg(%q) = %v, want %v", tc.alg, got, tc.want)
			}
		})
	}
}

func TestMustBuildStepUpChallenge(t *testing.T) {
	t.Parallel()

	result := MustBuildStepUpChallenge(StepUpChallenge{
		ACRValues:   []string{"urn:mace:incommon:iap:silver"},
		Description: "Step-up authentication required",
		Realm:       "api",
	})
	if result == "" {
		t.Fatal("MustBuildStepUpChallenge returned empty")
	}
	if !strings.Contains(result, "acr_values") {
		t.Error("MustBuildStepUpChallenge should include acr_values")
	}
	if !strings.Contains(result, "insufficient_user_authentication") {
		t.Error("MustBuildStepUpChallenge should include error")
	}
}

func TestBuildStepUpChallenge_Invalid(t *testing.T) {
	t.Parallel()

	_, err := BuildStepUpChallenge(StepUpChallenge{})
	if err == nil {
		t.Error("BuildStepUpChallenge with empty acr/max_age should error")
	}
}
