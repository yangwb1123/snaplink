// Package generate provides scaffolding for common component patterns.
// It generates boilerplate code for authenticators, stores, handlers, and grants,
// following the established architectural patterns in the codebase.
package generate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"unicode"
)

// Scaffold represents a code generation scaffold.
type Scaffold struct {
	// Type is the component type (authenticator, store, handler, grant).
	Type string
	// Name is the component name (e.g., "totp", "redis", "custom_auth").
	Name string
	// Package is the target package path.
	Package string
	// Description is a brief description of the component.
	Description string
}

// NewScaffold creates a new scaffold for the given type and name.
func NewScaffold(compType, name, pkg, desc string) *Scaffold {
	return &Scaffold{
		Type:        compType,
		Name:        name,
		Package:     pkg,
		Description: desc,
	}
}

// Generate creates the scaffold files in the specified directory.
func (s *Scaffold) Generate(outputDir string) error {
	switch strings.ToLower(s.Type) {
	case "authenticator":
		return s.generateAuthenticator(outputDir)
	case "store":
		return s.generateStore(outputDir)
	case "handler":
		return s.generateHandler(outputDir)
	case "grant":
		return s.generateGrant(outputDir)
	default:
		return fmt.Errorf("unknown scaffold type: %s", s.Type)
	}
}

// generateAuthenticator creates a new authenticator implementation.
func (s *Scaffold) generateAuthenticator(outputDir string) error {
	filename := filepath.Join(outputDir, fmt.Sprintf("%s.go", s.Name))
	if err := s.ensureDir(outputDir); err != nil {
		return err
	}
	return s.writeTemplate(filename, authenticatorTemplate, s.templateData())
}

// generateStore creates a new storage backend implementation.
func (s *Scaffold) generateStore(outputDir string) error {
	filename := filepath.Join(outputDir, fmt.Sprintf("%s_store.go", s.Name))
	if err := s.ensureDir(outputDir); err != nil {
		return err
	}
	return s.writeTemplate(filename, storeTemplate, s.templateData())
}

// generateHandler creates a new HTTP handler following the hexagonal pattern.
func (s *Scaffold) generateHandler(outputDir string) error {
	filename := filepath.Join(outputDir, fmt.Sprintf("%s_handler.go", s.Name))
	if err := s.ensureDir(outputDir); err != nil {
		return err
	}
	return s.writeTemplate(filename, handlerTemplate, s.templateData())
}

// generateGrant creates a new OAuth grant handler.
func (s *Scaffold) generateGrant(outputDir string) error {
	filename := filepath.Join(outputDir, fmt.Sprintf("%s_grant.go", s.Name))
	if err := s.ensureDir(outputDir); err != nil {
		return err
	}
	return s.writeTemplate(filename, grantTemplate, s.templateData())
}

// templateData builds the common template substitution set shared by every
// component kind. Package is deliberately NOT s.Package verbatim: --package
// is documented (and commonly passed) as a directory-shaped target like
// "infrastructure/redis" or "internal/handler", but a Go `package` clause
// must be a single bare identifier — passing the raw path through produced
// a syntactically invalid "package infrastructure/redis" (confirmed by
// actually compiling generated output). packageName reduces it to the final
// path segment, matching the real package name at that directory.
func (s *Scaffold) templateData() map[string]interface{} {
	return map[string]interface{}{
		"Name":        s.camelize(s.Name),
		"LowerName":   strings.ToLower(s.Name),
		"Description": s.Description,
		"Package":     packageName(s.Package),
	}
}

// packageName derives the Go package identifier from a (possibly nested)
// target package path such as "infrastructure/redis" or "internal/handler" —
// the last path segment ("redis", "handler"), since only that is a valid Go
// package-clause identifier.
func packageName(pkg string) string {
	pkg = strings.TrimSuffix(pkg, "/")
	if i := strings.LastIndex(pkg, "/"); i >= 0 {
		return pkg[i+1:]
	}
	return pkg
}

// ensureDir creates the output directory if it doesn't exist.
func (s *Scaffold) ensureDir(dir string) error {
	return os.MkdirAll(dir, 0755)
}

// writeTemplate writes a template to a file with the given data.
func (s *Scaffold) writeTemplate(filename, tmplText string, data interface{}) error {
	tmpl, err := template.New(filepath.Base(filename)).Parse(tmplText)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}

	fmt.Printf("✓ Generated %s\n", filename)
	return nil
}

// camelize converts a snake_case or kebab-case string to CamelCase.
func (s *Scaffold) camelize(str string) string {
	parts := strings.FieldsFunc(str, func(r rune) bool {
		return r == '_' || r == '-' || r == ' '
	})

	var result strings.Builder
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		runes := []rune(part)
		runes[0] = unicode.ToUpper(runes[0])
		result.WriteString(string(runes))
	}
	return result.String()
}
