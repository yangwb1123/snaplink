package ldapauth

import (
	"errors"
	"fmt"
	"strings"
)

func (c *Config) validateRequiredFields() error {
	if c.Name == "" {
		return errors.New("ldap: Name required")
	}
	if len(c.URLs) == 0 {
		return errors.New("ldap: at least one URL required")
	}
	if c.BaseDN == "" {
		return errors.New("ldap: BaseDN required")
	}

	// A non-empty DN with an empty password is an unauthenticated bind (RFC
	// 4513 §5.1.2), which can silently give the service search anonymous rights.
	// Explicit anonymous search (empty BindDN) stays allowed.
	if c.BindDN != "" && c.BindPassword == "" {
		return errors.New("ldap: BindPassword required when BindDN is set (an empty password is an unauthenticated bind)")
	}
	return nil
}

func (c *Config) validateTLS() error {
	scheme, err := c.urlsScheme()
	if err != nil {
		return err
	}

	// TLS settings configure encryption but do not activate it. Only LDAPS or
	// explicit StartTLS protects credentials; AllowInsecure is a dev-only opt-out.
	if scheme != "ldaps" && !c.StartTLS && !c.AllowInsecure {
		return errors.New("ldap: TLS required — use an ldaps:// URL or set StartTLS (set AllowInsecure only for development)")
	}
	// A supplied TLSConfig owns its verification policy; this acknowledgement
	// governs only the config built from the individual fields.
	if c.InsecureSkipVerify && !c.AllowInsecure && c.TLSConfig == nil {
		return errors.New("ldap: InsecureSkipVerify requires AllowInsecure (it disables certificate verification — development only)")
	}
	return nil
}

func (c *Config) validateUserFilter() error {
	filter := c.UserFilter
	if filter == "" {
		filter = DefaultUserFilter
	}
	// Without substitution, the filter matches the same set for every login.
	if !strings.Contains(filter, usernamePlaceholder) {
		return fmt.Errorf("ldap: UserFilter must contain the %q username placeholder, got %q", usernamePlaceholder, filter)
	}
	// Substitution supplies one argument; another %s would render as
	// "%!s(MISSING)" and corrupt the filter.
	if strings.Count(filter, usernamePlaceholder) != 1 {
		return fmt.Errorf("ldap: UserFilter must contain exactly one %q placeholder, got %q", usernamePlaceholder, filter)
	}
	return nil
}

func (c *Config) validateGroupSearch() error {
	// Validate even dead GroupFilter config alongside GroupAttribute: otherwise
	// removing GroupAttribute could expose a broken filter only at runtime.
	if c.GroupFilter != "" && strings.Count(c.GroupFilter, usernamePlaceholder) != 1 {
		return fmt.Errorf("ldap: GroupFilter must contain exactly one %q placeholder, got %q", usernamePlaceholder, c.GroupFilter)
	}

	// The reverse-membership search needs both its base and filter. The
	// GroupAttribute/memberOf path does not perform this second search.
	if c.GroupAttribute == "" && (c.GroupBaseDN != "" || c.GroupFilter != "") {
		if c.GroupBaseDN == "" || c.GroupFilter == "" {
			return errors.New("ldap: GroupBaseDN and GroupFilter must both be set for group-search resolution")
		}
	}
	return nil
}
