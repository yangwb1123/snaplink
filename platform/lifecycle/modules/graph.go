package modules

import (
	"fmt"
	"sort"
	"strings"
)

type catalog struct {
	definitions map[string]Definition
	dependents  map[string][]string
	order       []string
}

func buildCatalog(definitions []Definition) (*catalog, error) {
	result := &catalog{
		definitions: make(map[string]Definition, len(definitions)),
		dependents:  make(map[string][]string, len(definitions)),
	}
	for _, definition := range definitions {
		if err := addDefinition(result, definition); err != nil {
			return nil, err
		}
	}
	if err := result.validateDependencies(); err != nil {
		return nil, err
	}
	order, err := topologicalOrder(result.definitions)
	if err != nil {
		return nil, err
	}
	result.order = order
	return result, nil
}

func addDefinition(target *catalog, definition Definition) error {
	definition.ID = strings.TrimSpace(definition.ID)
	if !validModuleID(definition.ID) || definition.Factory == nil {
		return fmt.Errorf("%w: %q", ErrDefinitionInvalid, definition.ID)
	}
	if _, exists := target.definitions[definition.ID]; exists {
		return fmt.Errorf("%w: %s", ErrDefinitionDuplicate, definition.ID)
	}
	definition.Dependencies = normalizedDependencies(definition.Dependencies)
	target.definitions[definition.ID] = definition
	return nil
}

func (c *catalog) validateDependencies() error {
	for id, definition := range c.definitions {
		for _, dependency := range definition.Dependencies {
			if dependency == id {
				return fmt.Errorf("%w: %s", ErrDependencyCycle, id)
			}
			if _, exists := c.definitions[dependency]; !exists {
				return fmt.Errorf("%w: %s requires %s", ErrDependencyMissing, id, dependency)
			}
			c.dependents[dependency] = append(c.dependents[dependency], id)
		}
	}
	for id := range c.dependents {
		sort.Strings(c.dependents[id])
	}
	return nil
}

func topologicalOrder(definitions map[string]Definition) ([]string, error) {
	visited, visiting := make(map[string]bool), make(map[string]bool)
	ids := sortedDefinitionIDs(definitions)
	order := make([]string, 0, len(ids))
	var visit func(string) error
	visit = func(id string) error {
		if visiting[id] {
			return fmt.Errorf("%w: %s", ErrDependencyCycle, id)
		}
		if visited[id] {
			return nil
		}
		visiting[id] = true
		for _, dependency := range definitions[id].Dependencies {
			if err := visit(dependency); err != nil {
				return err
			}
		}
		delete(visiting, id)
		visited[id] = true
		order = append(order, id)
		return nil
	}
	for _, id := range ids {
		if err := visit(id); err != nil {
			return nil, err
		}
	}
	return order, nil
}

func sortedDefinitionIDs(definitions map[string]Definition) []string {
	ids := make([]string, 0, len(definitions))
	for id := range definitions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func normalizedDependencies(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; !exists {
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func validModuleID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for index, value := range id {
		if value >= 'a' && value <= 'z' || index > 0 && (value >= '0' && value <= '9' || value == '-') {
			continue
		}
		return false
	}
	return true
}
