package emailsmtp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRender_EscapesInterpolatedFields proves the html/template body
// rendering documented in templateEntry's doc comment actually neutralizes
// markup injected through an admin-controlled field (invitation's Role) —
// the concrete security property the design decision calls "not cosmetic".
func TestRender_EscapesInterpolatedFields(t *testing.T) {
	ts, err := newTemplateSet("")
	if err != nil {
		t.Fatal(err)
	}
	_, body, err := ts.render(tmplInvitation, tmplData{
		TenantID: "acme", Role: `<script>alert(1)</script>`, Token: "tok", LinkBaseURL: "https://x",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, "<script>") {
		t.Fatalf("raw <script> tag survived rendering — html/template auto-escaping did not fire: %q", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatalf("expected HTML-escaped Role in body, got %q", body)
	}
}

// TestRender_SubjectStripsHeaderInjection proves a newline embedded in a
// templated field cannot inject an extra RFC5322 header via the Subject
// line (header-injection hardening documented on templateSet.render).
func TestRender_SubjectStripsHeaderInjection(t *testing.T) {
	ts, err := newTemplateSet("")
	if err != nil {
		t.Fatal(err)
	}
	subject, _, err := ts.render(tmplInvitation, tmplData{
		TenantID: "acme\r\nBcc: attacker@evil.example", Role: "admin", Token: "tok", LinkBaseURL: "https://x",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(subject, "\r\n") {
		t.Fatalf("subject retains raw CR/LF — header injection possible: %q", subject)
	}
}

// TestNewTemplateSet_OverlayDir proves smtp.templates_dir overrides a subset
// of the five embedded defaults by name, leaving the others at their
// built-in content.
func TestNewTemplateSet_OverlayDir(t *testing.T) {
	dir := t.TempDir()
	custom := "Subject: Custom Reset\n\nCustom body with {{.Token}}.\n"
	if err := os.WriteFile(filepath.Join(dir, tmplPasswordReset+templateExt), []byte(custom), 0o600); err != nil {
		t.Fatal(err)
	}
	ts, err := newTemplateSet(dir)
	if err != nil {
		t.Fatal(err)
	}
	subject, body, err := ts.render(tmplPasswordReset, tmplData{Token: "tok-xyz"})
	if err != nil {
		t.Fatal(err)
	}
	if subject != "Custom Reset" {
		t.Fatalf("subject = %q, want overlay to win", subject)
	}
	if !strings.Contains(body, "tok-xyz") {
		t.Fatal("overlay body did not render the token")
	}
	// A non-overlaid name (otp) must still resolve to its embedded default.
	if _, _, err := ts.render(tmplOTP, tmplData{Code: "1"}); err != nil {
		t.Fatalf("non-overridden default template broke: %v", err)
	}
}

// TestRender_UnknownTemplate proves an unknown name is a caught error, not a
// panic or silent no-op.
func TestRender_UnknownTemplate(t *testing.T) {
	ts, err := newTemplateSet("")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ts.render("does-not-exist", tmplData{}); err == nil {
		t.Fatal("expected an error for an unknown template name")
	}
}
