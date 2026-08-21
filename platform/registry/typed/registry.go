// Package registrar provides the standard typed registrar used for operator
// extension seams. It is nested under the platform registry layer so the
// service-discovery and typed-registry primitives share one platform owner
// without adding another top-level platform directory.
package registrar

import (
	"fmt"
	"reflect"
	"sort"
	"sync"
)

// Registry is a name-addressed, write-once typed registry. Register panics
// on an empty name, a nil value, or a duplicate name.
type Registry[T any] struct {
	mu    sync.RWMutex
	items map[string]T
}

// New returns an empty Registry ready for registration.
func New[T any]() *Registry[T] {
	return &Registry[T]{items: make(map[string]T)}
}

// Register installs value under name and fails loudly on wiring mistakes.
func (r *Registry[T]) Register(name string, value T) {
	if name == "" {
		panic("registrar: empty name")
	}
	if isNilValue(value) {
		panic(fmt.Sprintf("registrar: nil value for %q", name))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.items[name]; dup {
		panic(fmt.Sprintf("registrar: %q already registered", name))
	}
	r.items[name] = value
}

// Lookup returns the value registered under name.
func (r *Registry[T]) Lookup(name string) (T, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	value, ok := r.items[name]
	return value, ok
}

// Names returns registered names in deterministic order.
func (r *Registry[T]) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.items))
	for name := range r.items {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Unregister removes a registered value. It is intended for test cleanup;
// production registration remains a boot-time, write-once operation.
func (r *Registry[T]) Unregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.items, name)
}

func isNilValue[T any](value T) bool {
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Func, reflect.Interface, reflect.Ptr, reflect.Map, reflect.Slice, reflect.Chan:
		return v.IsNil()
	}
	return false
}
