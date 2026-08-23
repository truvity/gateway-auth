// Package gatewayauth turns a gateway-authenticated request into a verified
// Identity, uniformly across the fleet's Go services.
//
// The login itself — the authorization code flow, the session, the redirect
// dance — belongs to the gateway in front of the service (oauth2-proxy as an
// Envoy Gateway HTTP ext_authz backend). The gateway forwards the caller's
// access token as a header and, at the SecurityPolicy, already denied anyone
// outside the route's groups. What is left for the service is the part a
// gateway cannot do on its behalf: knowing WHO the caller is and WHICH of the
// service's own roles they hold, because that changes which handlers refuse.
//
// The forwarded token is verified again here rather than trusted (the default
// mode). Not because the gateway is untrustworthy, but because "we are only
// reachable through the gateway" is a property of a NetworkPolicy — one YAML
// file away from being wrong — and a service that can mutate real state should
// not rest its authorization on that. A trust mode is offered for surfaces
// where the netpol genuinely is the boundary; it is opt-in, never a fallback.
//
// The package is deliberately un-bound from any one identity provider or
// gateway: the issuer is reached by OIDC discovery, the credential is pulled
// by a configurable TokenSource, and the claims are named by configuration.
// Zitadel and oauth2-proxy are the default PROFILE, not the contract.
package gatewayauth

import (
	"context"
	"errors"
)

// Identity is who the caller is, as far as a service is concerned.
//
// Roles are the raw claim values (the gateway's groups claim, e.g.
// "cluster-kernel:roster:operator"); each service maps these to its own
// permission model. Token is the verified access token, kept so a handler can
// call a downstream API (or userinfo) as the caller. Claims is every claim,
// for the app-specific reads the typed fields do not cover.
type Identity struct {
	Subject string
	Name    string
	Email   string
	Roles   []string
	Token   string
	Claims  map[string]any
}

// HasRole reports whether the caller holds the exact role value.
func (i Identity) HasRole(role string) bool {
	for _, r := range i.Roles {
		if r == role {
			return true
		}
	}

	return false
}

// HasAnyRole reports whether the caller holds at least one of the roles.
func (i Identity) HasAnyRole(roles ...string) bool {
	for _, role := range roles {
		if i.HasRole(role) {
			return true
		}
	}

	return false
}

// Headers is the minimal view of a request an Authenticator needs — one
// method, so every framework adapter (fiber, huma, connect, net/http) wraps its
// own request type in a few lines and the core stays framework-agnostic. A
// cookie-borne token is read by a TokenSource that parses the "Cookie" header,
// so no cookie accessor is needed here.
type Headers interface {
	// Get returns a header value, or "" if absent. Names are canonicalized
	// case-insensitively by the adapter.
	Get(name string) string
}

// Sentinel errors an adapter maps to a status. Authenticate reports only these
// two classes; authorization (does this caller hold a required role) is the
// adapter's or the app's job, not Authenticate's.
var (
	// ErrNoCredential means no token/identity was presented — the request
	// almost certainly did not come through the gateway. Adapters map it to
	// 401 Unauthorized.
	ErrNoCredential = errors.New("gatewayauth: no credential presented")
	// ErrInvalidToken means a credential was presented but failed
	// verification. Adapters map it to 401; the detailed reason is logged,
	// never returned to the caller.
	ErrInvalidToken = errors.New("gatewayauth: credential verification failed")
)

// Authenticator resolves a request into an Identity.
//
// Implementations: the JWKS verifier (NewVerifier / the profile presets), the
// header-trust authenticator (NewHeaderTrust), and the dev-only disabled one
// (NewDisabled). All three satisfy this interface, so an adapter is written
// once against it.
type Authenticator interface {
	// Authenticate extracts the caller's credential from the request,
	// verifies it (unless in trust mode), and returns the mapped Identity.
	// It returns ErrNoCredential or ErrInvalidToken on failure.
	Authenticate(ctx context.Context, h Headers) (Identity, error)
	// Enabled reports whether credentials are actually being verified. A
	// service can relax role checks in local development when this is false.
	Enabled() bool
}

// ContextKey is where the identity is parked on a context. A package-private
// struct type is the one key another package cannot collide with by accident.
type ContextKey struct{}

// WithIdentity attaches an identity to a context.
func WithIdentity(ctx context.Context, identity Identity) context.Context {
	return context.WithValue(ctx, ContextKey{}, identity)
}

// FromContext returns the identity attached by an adapter.
func FromContext(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(ContextKey{}).(Identity)

	return identity, ok
}

// ---------------------------------------------------------------------------
// Disabled — local development only.
// ---------------------------------------------------------------------------

// disabled verifies nothing and returns a fixed identity. Reachable only
// through an explicit opt-in, never as a fallback from a misconfiguration.
type disabled struct {
	identity Identity
}

// NewDisabled returns an authenticator that authorizes everybody as the given
// roles, for local development and tests. Pass the service's operator-level
// role(s) so dev matches production's most-privileged path.
func NewDisabled(roles ...string) Authenticator {
	return &disabled{identity: Identity{
		Subject: "local",
		Name:    "local operator",
		Email:   "local@localhost",
		Roles:   roles,
	}}
}

func (d *disabled) Enabled() bool { return false }

func (d *disabled) Authenticate(context.Context, Headers) (Identity, error) {
	return d.identity, nil
}
