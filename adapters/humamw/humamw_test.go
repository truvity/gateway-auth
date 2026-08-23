package humamw

import (
	"context"
	"net/http"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"

	gatewayauth "github.com/truvity/gateway-auth"
)

type fakeAuth struct {
	identity gatewayauth.Identity
	err      error
	enabled  bool
}

func (f fakeAuth) Authenticate(context.Context, gatewayauth.Headers) (gatewayauth.Identity, error) {
	return f.identity, f.err
}

func (f fakeAuth) Enabled() bool { return f.enabled }

type emptyOut struct{}

// setup builds a huma test API with the adapter registered, plus a protected
// operation (requires svc:operator) and an anonymous one.
func setup(t *testing.T, auth gatewayauth.Authenticator) humatest.TestAPI {
	t.Helper()

	_, api := humatest.New(t)
	Register(api, auth)

	huma.Register(api, huma.Operation{
		OperationID: "protected",
		Method:      http.MethodGet,
		Path:        "/protected",
		Security:    []map[string][]string{{SchemeName: {"svc:operator"}}},
	}, func(context.Context, *struct{}) (*emptyOut, error) {
		return &emptyOut{}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "public",
		Method:      http.MethodGet,
		Path:        "/public",
	}, func(context.Context, *struct{}) (*emptyOut, error) {
		return &emptyOut{}, nil
	})

	return api
}

func TestRegisterAddsSecurityScheme(t *testing.T) {
	t.Parallel()

	api := setup(t, fakeAuth{enabled: true})

	schemes := api.OpenAPI().Components.SecuritySchemes
	scheme, ok := schemes[SchemeName]
	if !ok {
		t.Fatalf("security scheme %q missing from the OpenAPI document", SchemeName)
	}

	if scheme.Type != "http" || scheme.Scheme != "bearer" {
		t.Fatalf("scheme = %#v, want an http/bearer scheme", scheme)
	}
}

func TestProtectedOperation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		auth       fakeAuth
		wantStatus int
	}{
		{
			name:       "no credential is 401",
			auth:       fakeAuth{err: gatewayauth.ErrNoCredential, enabled: true},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "invalid token is 401",
			auth:       fakeAuth{err: gatewayauth.ErrInvalidToken, enabled: true},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "authenticated but lacking the role is 403",
			auth:       fakeAuth{identity: gatewayauth.Identity{Roles: []string{"svc:viewer"}}, enabled: true},
			wantStatus: http.StatusForbidden,
		},
		{
			// The empty-output handler yields 204 No Content on success.
			name:       "holding the role passes",
			auth:       fakeAuth{identity: gatewayauth.Identity{Roles: []string{"svc:operator"}}, enabled: true},
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "disabled skips the role gate",
			auth:       fakeAuth{identity: gatewayauth.Identity{Roles: []string{"other"}}, enabled: false},
			wantStatus: http.StatusNoContent,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			api := setup(t, tc.auth)

			resp := api.Get("/protected")
			if resp.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", resp.Code, tc.wantStatus, resp.Body.String())
			}
		})
	}
}

func TestAnonymousOperationPasses(t *testing.T) {
	t.Parallel()

	// Even an authenticator that would reject everyone leaves an operation
	// without the scheme untouched.
	api := setup(t, fakeAuth{err: gatewayauth.ErrNoCredential, enabled: true})

	resp := api.Get("/public")
	if resp.Code != http.StatusNoContent {
		t.Fatalf("anonymous operation status = %d, want 204 (body: %s)", resp.Code, resp.Body.String())
	}
}

func TestRequiredRoles(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		op           *huma.Operation
		wantRoles    []string
		wantRequired bool
	}{
		{
			name:         "nil operation",
			op:           nil,
			wantRequired: false,
		},
		{
			name:         "no security declared",
			op:           &huma.Operation{},
			wantRequired: false,
		},
		{
			name: "scheme declared with roles",
			op: &huma.Operation{
				Security: []map[string][]string{{SchemeName: {"a", "b"}}},
			},
			wantRoles:    []string{"a", "b"},
			wantRequired: true,
		},
		{
			name: "another scheme only, ours absent",
			op: &huma.Operation{
				Security: []map[string][]string{{"other": {"x"}}},
			},
			wantRequired: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			roles, required := requiredRoles(tc.op)
			if required != tc.wantRequired {
				t.Fatalf("required = %v, want %v", required, tc.wantRequired)
			}

			if len(roles) != len(tc.wantRoles) {
				t.Fatalf("roles = %#v, want %#v", roles, tc.wantRoles)
			}

			for i := range roles {
				if roles[i] != tc.wantRoles[i] {
					t.Fatalf("roles = %#v, want %#v", roles, tc.wantRoles)
				}
			}
		})
	}
}
