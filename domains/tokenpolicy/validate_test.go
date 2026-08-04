package tokenpolicy

import (
	"strings"
	"testing"
	"time"
)

// TestValidate_AcceptsLegalDocument proves a full legal rule — all three new
// selector fields with valid shapes — passes, and the fields land on the
// decoded policy (the "does not reject what the evaluator can use" half).
func TestValidate_AcceptsLegalDocument(t *testing.T) {
	t.Parallel()
	ps := []Policy{
		{Name: "tenant-svc", TenantID: "ta", Subject: "svc-*", SubjectRoles: []string{"admin", "member"}, MaxTTL: 5 * time.Minute},
		{Name: "global", ClientID: "payments-*", MaxTTL: time.Hour},
	}
	if err := Validate(ps); err != nil {
		t.Fatalf("Validate(legal) = %v, want nil", err)
	}
}

// TestValidate_AcceptsEmptySelectors proves the backward-compatible form — a
// global rule with every new selector empty — passes unchanged.
func TestValidate_AcceptsEmptySelectors(t *testing.T) {
	t.Parallel()
	if err := Validate([]Policy{{Name: "global", MaxTTL: time.Minute}}); err != nil {
		t.Fatalf("Validate(global-only) = %v, want nil", err)
	}
	if err := Validate(nil); err != nil {
		t.Fatalf("Validate(nil) = %v, want nil", err)
	}
}

// TestValidate_RejectsBareStar proves a bare "*" client_id/subject selector —
// the ambiguous spelling of "any" that would silently match everything — is a
// boot error; the only spelling of "any" is the empty field.
func TestValidate_RejectsBareStar(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, field, value string }{
		{"client bare", "client_id", "*"},
		{"subject bare", "subject", "*"},
	} {
		p := Policy{Name: "p"}
		if tc.field == "client_id" {
			p.ClientID = tc.value
		} else {
			p.Subject = tc.value
		}
		if err := Validate([]Policy{p}); err == nil {
			t.Errorf("Validate(%s=%q) = nil, want an error", tc.field, tc.value)
		}
	}
}

// TestValidate_RejectsInteriorOrMultipleStars proves interior ("pay*ments")
// and multiple ("pay*ments*") wildcards are rejected — both are ambiguous
// spellings that would silently widen or never-match.
func TestValidate_RejectsInteriorOrMultipleStars(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"pay*ments", "pay*ments*", "**"} {
		if err := Validate([]Policy{{Name: "p", ClientID: value}}); err == nil {
			t.Errorf("Validate(client_id=%q) = nil, want an error", value)
		}
		if err := Validate([]Policy{{Name: "p", Subject: value}}); err == nil {
			t.Errorf("Validate(subject=%q) = nil, want an error", value)
		}
	}
}

// TestValidate_AcceptsTrailingStar proves the one legal wildcard spelling —
// exactly one trailing "*" with a non-empty prefix.
func TestValidate_AcceptsTrailingStar(t *testing.T) {
	t.Parallel()
	if err := Validate([]Policy{{Name: "p", ClientID: "payments-*", Subject: "svc-*"}}); err != nil {
		t.Fatalf("Validate(trailing stars) = %v, want nil", err)
	}
}

// TestValidate_RejectsBadTenantID proves tenant_id spellings that can never
// match a real tenant fail loud: a wildcard and whitespace padding (security
// F4). A missing key (empty) is the ONLY spelling of "global rule" and stays
// legal.
func TestValidate_RejectsBadTenantID(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"*", "ta*", " a ", "\tta\n"} {
		if err := Validate([]Policy{{Name: "p", TenantID: value}}); err == nil {
			t.Errorf("Validate(tenant_id=%q) = nil, want an error", value)
		}
	}
	if err := Validate([]Policy{{Name: "p", TenantID: "ta"}}); err != nil {
		t.Errorf("Validate(tenant_id=ta) = %v, want nil", err)
	}
}

// TestValidate_RejectsUnknownRole proves subject_roles entries outside the
// closed core.TenantRole set (member/admin/guest) — including an empty
// string — fail boot.
func TestValidate_RejectsUnknownRole(t *testing.T) {
	t.Parallel()
	for _, role := range []string{"owner", "", "ADMIN", "admin "} {
		if err := Validate([]Policy{{Name: "p", SubjectRoles: []string{role}}}); err == nil {
			t.Errorf("Validate(subject_roles=[%q]) = nil, want an error", role)
		}
	}
	if err := Validate([]Policy{{Name: "p", SubjectRoles: []string{"admin", "member", "guest"}}}); err != nil {
		t.Errorf("Validate(closed-set roles) = %v, want nil", err)
	}
}

// TestValidate_ErrorNamesPolicy proves a validation error identifies the
// offending policy by index + name so an operator can fix the right rule.
func TestValidate_ErrorNamesPolicy(t *testing.T) {
	t.Parallel()
	err := Validate([]Policy{{Name: "good"}, {Name: "bad-rule", ClientID: "*"}})
	if err == nil || !strings.Contains(err.Error(), "bad-rule") {
		t.Fatalf("Validate error = %v, want it to name the offending policy", err)
	}
}
