package gatewayauth

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/lestrrat-go/jwx/v4/jwt"
)

// verifier verifies the forwarded access token against the issuer's JWKS and
// maps its claims to an Identity. This is the default (recommended) mode.
type verifier struct {
	logger   *slog.Logger
	keys     *keySet
	source   TokenSource
	mapper   ClaimsMapper
	issuer   string
	audience string
	userinfo *userinfoFetcher // nil disables the display-claim fallback
	// displayCookie names the gateway's ID-token cookie; "" disables the
	// cookie-borne display-claim fallback.
	displayCookie string
}

func (v *verifier) Enabled() bool { return true }

func (v *verifier) Authenticate(ctx context.Context, h Headers) (Identity, error) {
	raw, ok := v.source.Token(h)
	if !ok {
		return Identity{}, ErrNoCredential
	}

	token, err := v.parse(raw)
	if err != nil {
		// The reason goes to the log, not the caller: telling an
		// unauthenticated client why its token failed helps it forge a better
		// one.
		v.logger.WarnContext(ctx, "token rejected", slog.Any("error", err))

		return Identity{}, ErrInvalidToken
	}

	identity := v.mapper.identity(token, raw)

	// Zitadel asserts profile claims into the ID token, not the access
	// token, so an access-token-only identity can lack name/email. Two
	// fallbacks, cheapest first: the gateway's ID-token cookie (verified,
	// same subject), then userinfo with the token that already proved
	// itself. Failures only degrade display.
	if identity.Name == "" && identity.Email == "" {
		v.fillFromDisplayCookie(ctx, h, &identity)
	}

	if v.userinfo != nil && identity.Name == "" && identity.Email == "" {
		v.userinfo.fill(ctx, raw, &identity)
	}

	return identity, nil
}

// fillFromDisplayCookie reads name/email from the gateway's ID-token cookie
// (Envoy Gateway's OIDC filter stores one as "IdToken"). The cookie is
// VERIFIED against the same key set and must carry the same subject as the
// access token — display data still only enters through a proven token. A
// browser drops cookies past ~4 KiB, so an ID token fat with role assertions
// may simply be absent; that is what the userinfo fallback is for.
func (v *verifier) fillFromDisplayCookie(ctx context.Context, h Headers, identity *Identity) {
	if v.displayCookie == "" {
		return
	}

	raw := cookieValue(h.Get("Cookie"), v.displayCookie)
	if raw == "" {
		return
	}

	token, err := v.parse(raw)
	if err != nil {
		v.logger.DebugContext(ctx, "id token cookie rejected", slog.Any("error", err))

		return
	}

	if subject, _ := token.Subject(); subject != identity.Subject {
		return
	}

	identity.Name = stringClaim(token, "name")
	identity.Email = stringClaim(token, "email")
}

// cookieValue extracts one cookie from a Cookie header, "" when absent.
func cookieValue(header, name string) string {
	for _, part := range strings.Split(header, ";") {
		k, val, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && k == name {
			return val
		}
	}

	return ""
}

// parse validates the token's signature, issuer, audience and expiry.
func (v *verifier) parse(raw string) (jwt.Token, error) {
	opts := []jwt.ParseOption{
		jwt.WithKeySet(v.keys.Set()),
		jwt.WithValidate(true),
		jwt.WithIssuer(v.issuer),
	}

	// An empty audience accepts any token this issuer minted. Behind a gateway
	// that already checked the audience this is the right default, and it
	// avoids naming the wrong value on providers whose access tokens carry a
	// project rather than a client.
	if v.audience != "" {
		opts = append(opts, jwt.WithAudience(v.audience))
	}

	token, err := jwt.ParseString(raw, opts...)
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	return token, nil
}

// ---------------------------------------------------------------------------
// Header trust — opt-in, no token verification.
// ---------------------------------------------------------------------------

// headerTrust builds an Identity from oauth2-proxy's pre-parsed identity
// headers WITHOUT verifying a token. For surfaces where the ingress-from-fleet
// NetworkPolicy is genuinely the trust boundary. It still requires the headers
// to be present, so a request that bypassed the proxy is rejected.
type headerTrust struct{}

func (headerTrust) Enabled() bool { return true }

func (headerTrust) Authenticate(_ context.Context, h Headers) (Identity, error) {
	subject := h.Get(HeaderUser)
	email := h.Get(HeaderEmail)

	if subject == "" && email == "" {
		return Identity{}, ErrNoCredential
	}

	name := subject
	if name == "" {
		name = email
	}

	return Identity{
		Subject: subject,
		Name:    name,
		Email:   email,
		Roles:   splitAndTrim(h.Get(HeaderGroups), ","),
		Token:   h.Get(HeaderAccessToken),
	}, nil
}
