package connectmw

import (
	"context"
	"testing"

	"connectrpc.com/connect"

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

// invoke runs one request through the interceptor. next records whether it ran
// and the identity it saw on the context.
func invoke(interceptor connect.UnaryInterceptorFunc) (called bool, seen gatewayauth.Identity, sawIdentity bool, err error) {
	next := func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		called = true
		seen, sawIdentity = gatewayauth.FromContext(ctx)

		return connect.NewResponse(&struct{}{}), nil
	}

	req := connect.NewRequest(&struct{}{})
	_, err = interceptor(next)(context.Background(), req)

	return called, seen, sawIdentity, err
}

func TestInterceptor(t *testing.T) {
	t.Parallel()

	t.Run("valid credential attaches identity and calls next", func(t *testing.T) {
		t.Parallel()

		auth := fakeAuth{identity: gatewayauth.Identity{Subject: "u-1"}, enabled: true}

		called, seen, sawIdentity, err := invoke(Interceptor(auth))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !called {
			t.Fatal("next was not called on success")
		}

		if !sawIdentity || seen.Subject != "u-1" {
			t.Fatalf("identity on context = (%#v, %v), want subject u-1 attached", seen, sawIdentity)
		}
	})

	rejections := []struct {
		name string
		err  error
	}{
		{"no credential", gatewayauth.ErrNoCredential},
		{"invalid token", gatewayauth.ErrInvalidToken},
	}

	for _, tc := range rejections {
		t.Run(tc.name+" is CodeUnauthenticated", func(t *testing.T) {
			t.Parallel()

			auth := fakeAuth{err: tc.err, enabled: true}

			called, _, _, err := invoke(Interceptor(auth))
			if called {
				t.Fatal("next must not run when authentication fails")
			}

			if connect.CodeOf(err) != connect.CodeUnauthenticated {
				t.Fatalf("code = %v, want CodeUnauthenticated (err: %v)", connect.CodeOf(err), err)
			}
		})
	}
}

func TestOptionalInterceptor(t *testing.T) {
	t.Parallel()

	t.Run("attaches identity when present", func(t *testing.T) {
		t.Parallel()

		auth := fakeAuth{identity: gatewayauth.Identity{Subject: "u-1"}, enabled: true}

		called, seen, sawIdentity, err := invoke(OptionalInterceptor(auth))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !called || !sawIdentity || seen.Subject != "u-1" {
			t.Fatalf("optional with credential: called=%v identity=(%#v,%v)", called, seen, sawIdentity)
		}
	})

	t.Run("proceeds anonymously when absent", func(t *testing.T) {
		t.Parallel()

		auth := fakeAuth{err: gatewayauth.ErrNoCredential, enabled: true}

		called, _, sawIdentity, err := invoke(OptionalInterceptor(auth))
		if err != nil {
			t.Fatalf("optional must not fail on a missing credential: %v", err)
		}

		if !called {
			t.Fatal("next must run even without a credential")
		}

		if sawIdentity {
			t.Fatal("no identity should be attached for an anonymous request")
		}
	})
}
