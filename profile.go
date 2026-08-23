package gatewayauth

import (
	"context"
	"fmt"
	"log/slog"
)

// Config configures a verifying Authenticator.
type Config struct {
	// Issuer is the OIDC issuer URL; discovery derives JWKS + userinfo from it.
	Issuer string
	// Audience, if set, is required in the token. Empty accepts any token the
	// issuer minted — the right default behind a gateway that already checked
	// audience, and it avoids naming the wrong value on providers whose access
	// tokens carry a project rather than a client.
	Audience string
	// Source pulls the token from the request. Nil uses DefaultSource().
	Source TokenSource
	// Claims names the claims mapped into an Identity. Zero value uses the
	// OIDC-standard names with "groups" for roles.
	Claims ClaimsMapper
	// UserinfoFallback fills Name/Email from the userinfo endpoint when the
	// access token carries neither. Off by default.
	UserinfoFallback bool
	// Logger; nil uses slog.Default().
	Logger *slog.Logger
}

// NewVerifier builds an Authenticator against the issuer's JWKS. Discovery and
// the first key fetch happen here, so an unreachable or misconfigured issuer
// fails at startup rather than on the first request.
func NewVerifier(ctx context.Context, cfg Config) (Authenticator, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("gatewayauth: issuer is required")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	source := cfg.Source
	if source == nil {
		source = DefaultSource()
	}

	found, err := discover(ctx, cfg.Issuer)
	if err != nil {
		return nil, err
	}

	keys, err := newKeySet(ctx, logger, found.JWKSURI)
	if err != nil {
		return nil, err
	}

	v := &verifier{
		logger:   logger,
		keys:     keys,
		source:   source,
		mapper:   cfg.Claims,
		issuer:   cfg.Issuer,
		audience: cfg.Audience,
	}

	if cfg.UserinfoFallback && found.UserinfoURI != "" {
		v.userinfo = newUserinfoFetcher(logger, found.UserinfoURI)
	}

	return v, nil
}

// NewHeaderTrust returns an Authenticator that trusts oauth2-proxy's forwarded
// identity headers WITHOUT verifying a token. Use only where the
// ingress-from-fleet NetworkPolicy is genuinely the trust boundary; the
// verifying mode is the recommended default.
func NewHeaderTrust() Authenticator { return headerTrust{} }

// OAuth2ProxyOIDC is the fleet's default profile: verify the access token
// oauth2-proxy forwards, against the given issuer, mapping the rbac-mapper
// "groups" claim to roles, with userinfo fallback for display names.
//
// Every seam is still overridable via NewVerifier(Config{...}); this is the
// one-liner for the common case, not a different contract.
func OAuth2ProxyOIDC(ctx context.Context, logger *slog.Logger, issuer string) (Authenticator, error) {
	return NewVerifier(ctx, Config{
		Issuer:           issuer,
		Source:           DefaultSource(),
		UserinfoFallback: true,
		Logger:           logger,
	})
}
