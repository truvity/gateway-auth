// Package fibermw adapts gatewayauth to Fiber v3.
package fibermw

import (
	"errors"

	"github.com/gofiber/fiber/v3"

	gatewayauth "github.com/truvity/gateway-auth"
)

// fiberHeaders wraps a Fiber request as gatewayauth.Headers.
type fiberHeaders struct{ c fiber.Ctx }

func (f fiberHeaders) Get(name string) string { return f.c.Get(name) }

// Require authenticates the caller, attaches the Identity, and rejects anyone
// without a valid credential with 401.
func Require(auth gatewayauth.Authenticator) fiber.Handler {
	return func(c fiber.Ctx) error {
		identity, err := auth.Authenticate(c.Context(), fiberHeaders{c})
		if err != nil {
			return statusFor(err)
		}

		attach(c, identity)

		return c.Next()
	}
}

// attach parks the identity where BOTH kinds of handler find it: fiber
// Locals for fiber handlers, and the fasthttp request context's user values
// for net/http handlers adapted into fiber (a ConnectRPC service behind the
// fiber adaptor reads it with gatewayauth.FromContext) — fiber Locals do not
// cross that boundary on their own.
func attach(c fiber.Ctx, identity gatewayauth.Identity) {
	c.Locals(gatewayauth.ContextKey{}, identity)
	c.RequestCtx().SetUserValue(gatewayauth.ContextKey{}, identity)
}

// Optional attaches an Identity when one is present and valid, and otherwise
// continues anonymously — for a process serving protected and public routes
// together (eudi's demo alongside its wallet/issuer surfaces).
func Optional(auth gatewayauth.Authenticator) fiber.Handler {
	return func(c fiber.Ctx) error {
		if identity, err := auth.Authenticate(c.Context(), fiberHeaders{c}); err == nil {
			attach(c, identity)
		}

		return c.Next()
	}
}

// RequireRoles authenticates and additionally requires at least one of the
// roles (403 otherwise). Role checks are skipped when the authenticator is
// disabled (local development).
func RequireRoles(auth gatewayauth.Authenticator, roles ...string) fiber.Handler {
	return func(c fiber.Ctx) error {
		identity, err := auth.Authenticate(c.Context(), fiberHeaders{c})
		if err != nil {
			return statusFor(err)
		}

		if auth.Enabled() && !identity.HasAnyRole(roles...) {
			return fiber.NewError(fiber.StatusForbidden, "your account holds none of the required roles")
		}

		attach(c, identity)

		return c.Next()
	}
}

// From returns the Identity attached to a Fiber request.
func From(c fiber.Ctx) (gatewayauth.Identity, bool) {
	identity, ok := c.Locals(gatewayauth.ContextKey{}).(gatewayauth.Identity)

	return identity, ok
}

// statusFor maps the sentinel errors to 401 without leaking why to the caller.
func statusFor(err error) error {
	switch {
	case errors.Is(err, gatewayauth.ErrNoCredential):
		return fiber.NewError(fiber.StatusUnauthorized, "authentication required: reach this service through the gateway")
	case errors.Is(err, gatewayauth.ErrInvalidToken):
		return fiber.NewError(fiber.StatusUnauthorized, "invalid credential")
	default:
		return fiber.NewError(fiber.StatusUnauthorized, "authentication failed")
	}
}
