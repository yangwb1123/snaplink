package emailsmtp

import (
	"bytes"
	"embed"
	"fmt"
	htmltemplate "html/template"
	"io/fs"
	"os"
	"path"
	"strings"
	texttemplate "text/template"
)

// defaultTemplateFS embeds the five default .tmpl files. They live directly
// beside this file (NOT in a templates/ subdirectory): infrastructure/
// defaultimpl/emailsmtp is already at maxDirDepth (3) in
// maxdepth_test.go/TestArchitecture_DirectoryDepth, so one more nesting level
// would fail that gate. go:embed does not require a dedicated subdirectory —
// docs/examples/playground/main.go embeds a sibling file the same way.
//
//go:embed *.tmpl
var defaultTemplateFS embed.FS

// Stable template-name consts (no literal leaks) — also the .tmpl basenames.
const (
	tmplPasswordReset     = "password_reset"
	tmplEmailVerification = "email_verification"
	tmplEmailChange       = "email_change"
	tmplInvitation        = "invitation"
	tmplOTP               = "otp"
	tmplNotification      = "notification"
)

const (
	templateExt   = ".tmpl"
	subjectPrefix = "Subject: "
)

// templateEntry pairs the two renderings AGENTS.md's design calls for: a
// text/template subject line (no HTML context, so no escaping) and an
// html/template body. The body is delivered as the plain-text message
// content, but rendering it through html/template still auto-escapes any
// interpolated field (Email, Role, TenantID — some of which are attacker- or
// admin-supplied) as defense-in-depth against control/markup injection.
// Auto-escaping is a security property here, not cosmetic.
type templateEntry struct {
	subject *texttemplate.Template
	body    *htmltemplate.Template
}

// templateSet holds one parsed templateEntry per stable name.
type templateSet struct {
	entries map[string]templateEntry
}

// newTemplateSet parses the embedded defaults, then overlays dir when
// non-empty — a filesystem override lets an operator replace a subset of the
// five built-ins (matching names win) without shipping all five.
func newTemplateSet(dir string) (*templateSet, error) {
	ts := &templateSet{entries: map[string]templateEntry{}}
	if err := ts.load(defaultTemplateFS, "."); err != nil {
		return nil, err
	}
	if strings.TrimSpace(dir) == "" {
		return ts, nil
	}
	if err := ts.load(os.DirFS(dir), "."); err != nil {
		return nil, fmt.Errorf("emailsmtp: templates_dir %q: %w", dir, err)
	}
	return ts, nil
}

// load parses every *.tmpl file directly under root in fsys, overwriting any
// same-named entry already present (the override mechanism above).
func (ts *templateSet) load(fsys fs.FS, root string) error {
	entries, err := fs.ReadDir(fsys, root)
	if err != nil {
		return fmt.Errorf("emailsmtp: read templates: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), templateExt) {
			continue
		}
		raw, err := fs.ReadFile(fsys, path.Join(root, e.Name()))
		if err != nil {
			return fmt.Errorf("emailsmtp: read %s: %w", e.Name(), err)
		}
		name := strings.TrimSuffix(e.Name(), templateExt)
		entry, err := parseTemplateEntry(name, string(raw))
		if err != nil {
			return err
		}
		ts.entries[name] = entry
	}
	return nil
}

// parseTemplateEntry splits raw on its first line ("Subject: ...") from the
// rest (the body) and parses each half with its own template engine.
func parseTemplateEntry(name, raw string) (templateEntry, error) {
	subjectLine, body, found := strings.Cut(raw, "\n")
	if !found {
		return templateEntry{}, fmt.Errorf("emailsmtp: template %q has no body", name)
	}
	subjectLine = strings.TrimPrefix(strings.TrimSpace(subjectLine), subjectPrefix)
	st, err := texttemplate.New(name + "-subject").Parse(subjectLine)
	if err != nil {
		return templateEntry{}, fmt.Errorf("emailsmtp: parse subject %q: %w", name, err)
	}
	bt, err := htmltemplate.New(name + "-body").Parse(strings.TrimSpace(body))
	if err != nil {
		return templateEntry{}, fmt.Errorf("emailsmtp: parse body %q: %w", name, err)
	}
	return templateEntry{subject: st, body: bt}, nil
}

// render executes the named template pair against data, returning the
// (subject, body) the message is built from.
func (ts *templateSet) render(name string, data tmplData) (string, string, error) {
	entry, ok := ts.entries[name]
	if !ok {
		return "", "", fmt.Errorf("emailsmtp: unknown template %q", name)
	}
	var subjBuf, bodyBuf bytes.Buffer
	if err := entry.subject.Execute(&subjBuf, data); err != nil {
		return "", "", fmt.Errorf("emailsmtp: render subject %q: %w", name, err)
	}
	if err := entry.body.Execute(&bodyBuf, data); err != nil {
		return "", "", fmt.Errorf("emailsmtp: render body %q: %w", name, err)
	}
	// A subject is a single RFC5322 header value: strip any embedded CR/LF so
	// a templated field (e.g. invitation's TenantID) can never inject an
	// extra header (header-injection hardening).
	subject := strings.NewReplacer("\r", " ", "\n", " ").Replace(subjBuf.String())
	return strings.TrimSpace(subject), bodyBuf.String(), nil
}
