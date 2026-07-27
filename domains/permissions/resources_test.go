package permissions_test

import (
	"errors"
	"testing"

	"github.com/yangwb1123/snaplink/domains/permissions"
)

func httpResource(id string) *permissions.Resource {
	return &permissions.Resource{
		ID:   id,
		Type: permissions.ResourceTypeHTTPAPI,
		Name: id,
		Attributes: map[string]string{
			"method": "GET",
			"path":   "/api/v1/users",
		},
	}
}

func TestValidate_HTTPAPIHappy(t *testing.T) {
	t.Parallel()
	if err := httpResource("r-1").Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_RejectsMissingID(t *testing.T) {
	t.Parallel()
	r := httpResource("")
	if err := r.Validate(); !errors.Is(err, permissions.ErrInvalidResource) {
		t.Errorf("err=%v", err)
	}
}

func TestValidate_RejectsMissingType(t *testing.T) {
	t.Parallel()
	r := httpResource("r-1")
	r.Type = ""
	if err := r.Validate(); !errors.Is(err, permissions.ErrInvalidResource) {
		t.Errorf("err=%v", err)
	}
}

func TestValidate_RejectsMissingName(t *testing.T) {
	t.Parallel()
	r := httpResource("r-1")
	r.Name = ""
	if err := r.Validate(); !errors.Is(err, permissions.ErrInvalidResource) {
		t.Errorf("err=%v", err)
	}
}

func TestValidate_RejectsBadRequireMode(t *testing.T) {
	t.Parallel()
	r := httpResource("r-1")
	r.RequireMode = "maybe"
	if err := r.Validate(); !errors.Is(err, permissions.ErrInvalidResource) {
		t.Errorf("err=%v", err)
	}
}

func TestValidate_HTTPAPIRequiresMethodAndPath(t *testing.T) {
	t.Parallel()
	cases := map[string]map[string]string{
		"missing method": {"path": "/x"},
		"missing path":   {"method": "GET"},
		"empty values":   {"method": "", "path": ""},
	}
	for name, attrs := range cases {
		t.Run(name, func(t *testing.T) {
			r := &permissions.Resource{ID: "r-1", Type: permissions.ResourceTypeHTTPAPI, Name: "x", Attributes: attrs}
			if err := r.Validate(); !errors.Is(err, permissions.ErrInvalidResource) {
				t.Errorf("err=%v want ErrInvalidResource", err)
			}
		})
	}
}

func TestValidate_GRPCAPIRequiresServiceAndMethod(t *testing.T) {
	t.Parallel()
	r := &permissions.Resource{
		ID: "r-1", Type: permissions.ResourceTypeGRPCAPI, Name: "x",
		Attributes: map[string]string{"service": "snaplink.user.v1.UserService"},
	}
	if err := r.Validate(); !errors.Is(err, permissions.ErrInvalidResource) {
		t.Errorf("err=%v", err)
	}
}

func TestValidate_GraphQLAPIRequiresOpAndField(t *testing.T) {
	t.Parallel()
	r := &permissions.Resource{
		ID: "r-1", Type: permissions.ResourceTypeGraphQLAPI, Name: "x",
		Attributes: map[string]string{"op": "mutation"},
	}
	if err := r.Validate(); !errors.Is(err, permissions.ErrInvalidResource) {
		t.Errorf("err=%v", err)
	}
}

func TestValidate_PageRequiresRoute(t *testing.T) {
	t.Parallel()
	r := &permissions.Resource{ID: "r-1", Type: permissions.ResourceTypePage, Name: "x"}
	if err := r.Validate(); !errors.Is(err, permissions.ErrInvalidResource) {
		t.Errorf("err=%v", err)
	}
}

func TestValidate_JSFnRequiresRouteAndSymbol(t *testing.T) {
	t.Parallel()
	r := &permissions.Resource{
		ID: "r-1", Type: permissions.ResourceTypeJSFn, Name: "x",
		Attributes: map[string]string{"route": "/admin"},
	}
	if err := r.Validate(); !errors.Is(err, permissions.ErrInvalidResource) {
		t.Errorf("err=%v", err)
	}
}

func TestValidate_UIElementRequiresSelector(t *testing.T) {
	t.Parallel()
	r := &permissions.Resource{ID: "r-1", Type: permissions.ResourceTypeUIElement, Name: "x"}
	if err := r.Validate(); !errors.Is(err, permissions.ErrInvalidResource) {
		t.Errorf("err=%v", err)
	}
}

func TestValidate_UnknownTypeAccepted(t *testing.T) {
	t.Parallel()
	// Custom types are allowed — backends define their own attribute
	// contract. Validate only enforces the documented first-party set.
	r := &permissions.Resource{ID: "r-1", Type: "custom_type", Name: "x"}
	if err := r.Validate(); err != nil {
		t.Errorf("custom types should pass Validate: %v", err)
	}
}

func TestEffectiveRequireMode_DefaultsToAny(t *testing.T) {
	t.Parallel()
	r := &permissions.Resource{}
	if r.EffectiveRequireMode() != permissions.RequireAny {
		t.Errorf("default = %q", r.EffectiveRequireMode())
	}
}

func TestEffectiveRequireMode_PreservesExplicit(t *testing.T) {
	t.Parallel()
	r := &permissions.Resource{RequireMode: permissions.RequireAll}
	if r.EffectiveRequireMode() != permissions.RequireAll {
		t.Errorf("explicit ignored")
	}
}
