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

	data := map[string]interface{}{
		"Name":        s.camelize(s.Name),
		"LowerName":   strings.ToLower(s.Name),
		"Description": s.Description,
		"Package":     s.Package,
	}

	return s.writeTemplate(filename, authenticatorTemplate, data)
}

// generateStore creates a new storage backend implementation.
func (s *Scaffold) generateStore(outputDir string) error {
	filename := filepath.Join(outputDir, fmt.Sprintf("%s_store.go", s.Name))
	if err := s.ensureDir(outputDir); err != nil {
		return err
	}

	data := map[string]interface{}{
		"Name":        s.camelize(s.Name),
		"LowerName":   strings.ToLower(s.Name),
		"Description": s.Description,
		"Package":     s.Package,
	}

	return s.writeTemplate(filename, storeTemplate, data)
}

// generateHandler creates a new HTTP handler following the hexagonal pattern.
func (s *Scaffold) generateHandler(outputDir string) error {
	filename := filepath.Join(outputDir, fmt.Sprintf("%s_handler.go", s.Name))
	if err := s.ensureDir(outputDir); err != nil {
		return err
	}

	data := map[string]interface{}{
		"Name":        s.camelize(s.Name),
		"LowerName":   strings.ToLower(s.Name),
		"Description": s.Description,
		"Package":     s.Package,
	}

	return s.writeTemplate(filename, handlerTemplate, data)
}

// generateGrant creates a new OAuth grant handler.
func (s *Scaffold) generateGrant(outputDir string) error {
	filename := filepath.Join(outputDir, fmt.Sprintf("%s_grant.go", s.Name))
	if err := s.ensureDir(outputDir); err != nil {
		return err
	}

	data := map[string]interface{}{
		"Name":        s.camelize(s.Name),
		"LowerName":   strings.ToLower(s.Name),
		"Description": s.Description,
		"Package":     s.Package,
	}

	return s.writeTemplate(filename, grantTemplate, data)
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
