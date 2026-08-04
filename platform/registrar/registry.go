// Package registrar provides the standard typed registrar used for every
// operator-extension seam in the server (SAML handler factories, external
// KMS/HSM signers, and any future named-factory surface). It exists so a
// hand-rolled mutex+map registry is never written twice: registration is
// panic-on-mistake (empty name, nil value, duplicate name — all
// unrecoverable wiring errors), lookup is read-only, and Names() is
// deterministic (sorted) for boot-time diagnostics.
//
// Registrars are process-local and name-addressed by CONFIGURATION (e.g.
// `saml.handler` selects a factory by name), so they are the in-process
// compile-time extension seam for forked binaries. They are NOT hot-plugin
// registries: nothing here can add or remove entries after startup, and
// installable third-party code must not be smuggled in through them (see
// docs/plugin-system.md).
package registrar

import (
	"fmt"
	"reflect"
	"sort"
	"sync"
)

// Registry is a name-addressed, write-once typed registry. Register panics
// on an empty name, a nil value, or a duplicate name — all three are
// unrecoverable wiring mistakes that must fail the boot loudly rather than
// silently pick a winner. Lookup and Names are safe for concurrent use.
type Registry[T any] struct {
	mu    sync.RWMutex
	items map[string]T
}

// New returns an empty Registry ready for registration.
func New[T any]() *Registry[T] {
	return &Registry[T]{items: make(map[string]T)}
}

// Register installs value under name. Panics on an empty name, a nil value
// (for nilable kinds: funcs, interfaces, pointers, maps, slices, chans),
// or a duplicate name — mirroring the pre-registrar hand-rolled registries'
// fail-loud contract so existing callers keep their boot-time diagnostics.
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

// Names returns the sorted names of every registered value, for
// boot-time diagnostics that must not depend on map iteration order.
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

// Unregister removes the value registered under name. It exists as the
// test seam: package-global registries must be cleanable across subtests
// and -count>1 runs, and production has no reason to call it — registration
// is a boot-time, write-once operation, and removing an entry at runtime
// would violate the extension seam's static contract (see the package
// comment). Removing a name that is not registered is a no-op.
func (r *Registry[T]) Unregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.items, name)
}

// isNilValue reports whether value is nil when its kind CAN be nil (func,
// interface, pointer, map, slice, chan). Non-nilable kinds (structs, ints)
// are never nil, so they always pass. Zero T is NOT rejected: a struct
// zero value can be a legitimate registered value.
func isNilValue[T any](value T) bool {
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Func, reflect.Interface, reflect.Ptr, reflect.Map, reflect.Slice, reflect.Chan:
		return v.IsNil()
	}
	return false
}
