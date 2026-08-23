package fibermw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"

	gatewayauth "github.com/truvity/gateway-auth"
)

// fakeAuth is an inline Authenticator: it ignores the request and returns
// whatever the test configured, so the adapter's status mapping can be
// exercised without a real token.
type fakeAuth struct {
	identity gatewayauth.Identity
	err      error
	enabled  bool
}

func (f fakeAuth) Authenticate(context.Context, gatewayauth.Headers) (gatewayauth.Identity, error) {
	return f.identity, f.err
}

func (f fakeAuth) Enabled() bool { return f.enabled }

// run installs handler as the middleware on GET / and reports the status plus
// the identity the terminal handler saw.
func run(t *testing.T, mw fiber.Handler) (int, gatewayauth.Identity, bool) {
	t.Helper()

	var (
		seen gatewayauth.Identity
		ok   bool
	)

	app := fiber.New()
	app.Use(mw)
	app.Get("/", func(c fiber.Ctx) error {
		seen, ok = From(c)

		return c.SendStatus(fiber.StatusOK)
	})

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/", http.NoBody))
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	defer func() { _ = resp.Body.Close() }()

	return resp.StatusCode, seen, ok
}

func TestRequire(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		auth       fakeAuth
		wantStatus int
		wantSeen   bool
	}{
		{
			name:       "no credential is 401",
			auth:       fakeAuth{err: gatewayauth.ErrNoCredential, enabled: true},
			wantStatus: fiber.StatusUnauthorized,
		},
		{
			name:       "invalid token is 401",
			auth:       fakeAuth{err: gatewayauth.ErrInvalidToken, enabled: true},
			wantStatus: fiber.StatusUnauthorized,
		},
		{
			name:       "valid credential passes and attaches identity",
			auth:       fakeAuth{identity: gatewayauth.Identity{Subject: "u-1"}, enabled: true},
			wantStatus: fiber.StatusOK,
			wantSeen:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			status, id, ok := run(t, Require(tc.auth))
			if status != tc.wantStatus {
				t.Fatalf("status = %d, want %d", status, tc.wantStatus)
			}

			if ok != tc.wantSeen {
				t.Fatalf("identity attached = %v, want %v", ok, tc.wantSeen)
			}

			if tc.wantSeen && id.Subject != "u-1" {
				t.Fatalf("From(c) = %#v, want subject u-1", id)
			}
		})
	}
}

func TestOptional(t *testing.T) {
	t.Parallel()

	// Missing credential still passes through, anonymously.
	status, _, ok := run(t, Optional(fakeAuth{err: gatewayauth.ErrNoCredential, enabled: true}))
	if status != fiber.StatusOK {
		t.Fatalf("anonymous status = %d, want 200", status)
	}

	if ok {
		t.Fatal("no identity should be attached for an anonymous request")
	}

	// A valid credential is attached.
	status, id, ok := run(t, Optional(fakeAuth{identity: gatewayauth.Identity{Subject: "u-1"}, enabled: true}))
	if status != fiber.StatusOK || !ok || id.Subject != "u-1" {
		t.Fatalf("authenticated optional = (%d, %v, %#v)", status, ok, id)
	}
}

func TestRequireRoles(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		auth       fakeAuth
		roles      []string
		wantStatus int
	}{
		{
			name:       "no credential is 401 before any role check",
			auth:       fakeAuth{err: gatewayauth.ErrNoCredential, enabled: true},
			roles:      []string{"svc:operator"},
			wantStatus: fiber.StatusUnauthorized,
		},
		{
			name:       "authenticated but lacking the role is 403",
			auth:       fakeAuth{identity: gatewayauth.Identity{Roles: []string{"svc:viewer"}}, enabled: true},
			roles:      []string{"svc:operator"},
			wantStatus: fiber.StatusForbidden,
		},
		{
			name:       "holding the role is 200",
			auth:       fakeAuth{identity: gatewayauth.Identity{Roles: []string{"svc:operator"}}, enabled: true},
			roles:      []string{"svc:operator"},
			wantStatus: fiber.StatusOK,
		},
		{
			// A disabled authenticator (local dev) skips the role gate.
			name:       "disabled skips the role check",
			auth:       fakeAuth{identity: gatewayauth.Identity{Roles: []string{"other"}}, enabled: false},
			roles:      []string{"svc:operator"},
			wantStatus: fiber.StatusOK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			status, _, _ := run(t, RequireRoles(tc.auth, tc.roles...))
			if status != tc.wantStatus {
				t.Fatalf("status = %d, want %d", status, tc.wantStatus)
			}
		})
	}
}
