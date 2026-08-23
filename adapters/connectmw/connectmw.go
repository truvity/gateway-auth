// Package connectmw adapts gatewayauth to connectrpc as a unary interceptor.
//
// The interceptor attaches the caller's Identity to the context; handlers read
// it with gatewayauth.FromContext and enforce their own roles, because
// connect carries no per-procedure security metadata the way Huma does.
package connectmw

import (
	"context"
	"errors"
	"net/http"

	"connectrpc.com/connect"

	gatewayauth "github.com/truvity/gateway-auth"
)

type connectHeaders struct{ h http.Header }

func (c connectHeaders) Get(name string) string { return c.h.Get(name) }

// Interceptor authenticates every unary request and attaches the Identity to
// the context, rejecting callers without a valid credential with
// CodeUnauthenticated.
func Interceptor(auth gatewayauth.Authenticator) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			identity, err := auth.Authenticate(ctx, connectHeaders{req.Header()})
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated,
					errors.New("authentication required"))
			}

			return next(gatewayauth.WithIdentity(ctx, identity), req)
		}
	}
}

// OptionalInterceptor attaches an Identity when one is present and valid, and
// otherwise proceeds anonymously.
func OptionalInterceptor(auth gatewayauth.Authenticator) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if identity, err := auth.Authenticate(ctx, connectHeaders{req.Header()}); err == nil {
				ctx = gatewayauth.WithIdentity(ctx, identity)
			}

			return next(ctx, req)
		}
	}
}
