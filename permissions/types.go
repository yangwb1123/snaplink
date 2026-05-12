package permissions

// Permission is a single capability code, optionally scoped to a resource.
// Codes use the "domain:action" convention ("user:read", "order:create"),
// with "*" allowed as a wildcard segment ("user:*", "*").
type Permission struct {
	Code     string `json:"code" yaml:"code"`
	Resource string `json:"resource,omitempty" yaml:"resource,omitempty"`
}

// Role bundles permissions and is assigned to users on a per-app basis.
type Role struct {
	Code        string   `json:"code" yaml:"code"`
	Name        string   `json:"name,omitempty" yaml:"name,omitempty"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	Permissions []string `json:"permissions" yaml:"permissions"`
}

// Button is a finer-grained UI control gated by a permission code.
type Button struct {
	Code       string `json:"code" yaml:"code"`
	Name       string `json:"name,omitempty" yaml:"name,omitempty"`
	Permission string `json:"permission,omitempty" yaml:"permission,omitempty"`
}

// MenuItem is one node in the menu tree. Permission, when set, gates whether
// the node is visible to the user. Buttons hang off a leaf for inline actions.
type MenuItem struct {
	ID         string     `json:"id" yaml:"id"`
	Name       string     `json:"name" yaml:"name"`
	Path       string     `json:"path,omitempty" yaml:"path,omitempty"`
	Icon       string     `json:"icon,omitempty" yaml:"icon,omitempty"`
	Permission string     `json:"permission,omitempty" yaml:"permission,omitempty"`
	Buttons    []Button   `json:"buttons,omitempty" yaml:"buttons,omitempty"`
	Children   []MenuItem `json:"children,omitempty" yaml:"children,omitempty"`
}

// MenuTree is the top-level navigation, already filtered for the requesting user.
type MenuTree []MenuItem
