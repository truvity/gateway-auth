package gatewayauth

import "strings"

// Header names the fleet's gateway (oauth2-proxy) sets, plus Authorization.
const (
	// HeaderAccessToken carries the verified access token oauth2-proxy
	// forwards (set_xauthrequest + pass_access_token). Not "Bearer"-prefixed.
	HeaderAccessToken = "X-Auth-Request-Access-Token" //nolint:gosec // G101 false positive: an HTTP header NAME, not a credential.
	// HeaderUser / HeaderEmail / HeaderGroups are oauth2-proxy's pre-parsed
	// identity headers — used by the trust-mode authenticator only.
	HeaderUser   = "X-Auth-Request-User"
	HeaderEmail  = "X-Auth-Request-Email"
	HeaderGroups = "X-Auth-Request-Groups"
	// HeaderAuthorization is the standard bearer header, for direct API
	// callers and tests.
	HeaderAuthorization = "Authorization"
)

// TokenSource pulls a raw (still-encoded) token out of a request.
type TokenSource interface {
	Token(h Headers) (raw string, ok bool)
}

// HeaderSource reads a token from one request header.
//
// Scheme, if set, is stripped case-insensitively together with a following
// space: Scheme "Bearer" turns "Bearer abc" into "abc" (RFC 7235 makes the
// scheme case-insensitive, and proxies do vary it). Scheme "" reads the header
// verbatim — how oauth2-proxy sets X-Auth-Request-Access-Token.
type HeaderSource struct {
	Name   string
	Scheme string
}

// Token implements TokenSource.
func (s HeaderSource) Token(h Headers) (string, bool) {
	value := strings.TrimSpace(h.Get(s.Name))
	if value == "" {
		return "", false
	}

	if s.Scheme == "" {
		return value, true
	}

	prefix := s.Scheme + " "
	if len(value) < len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return "", false
	}

	token := strings.TrimSpace(value[len(prefix):])

	return token, token != ""
}

// ChainSource tries each source in order and returns the first token found.
type ChainSource []TokenSource

// Token implements TokenSource.
func (c ChainSource) Token(h Headers) (string, bool) {
	for _, source := range c {
		if raw, ok := source.Token(h); ok {
			return raw, true
		}
	}

	return "", false
}

// OAuth2ProxyAccessToken reads the access token oauth2-proxy injects.
func OAuth2ProxyAccessToken() TokenSource { return HeaderSource{Name: HeaderAccessToken} }

// AuthorizationBearer reads a bearer token from the Authorization header.
func AuthorizationBearer() TokenSource {
	return HeaderSource{Name: HeaderAuthorization, Scheme: "Bearer"}
}

// DefaultSource tries the oauth2-proxy header first, then Authorization —
// covering both a gateway-fronted request and a direct API caller.
func DefaultSource() TokenSource {
	return ChainSource{OAuth2ProxyAccessToken(), AuthorizationBearer()}
}

// splitAndTrim splits on sep and drops empty/whitespace entries — for the
// comma-separated groups header.
func splitAndTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))

	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}

	if len(out) == 0 {
		return nil
	}

	return out
}

// ForwardAuthorization renders the caller's credential as an Authorization
// header value for a downstream call made ON BEHALF of the caller (a console
// forwarding the operator's token to its broker, say). It prefers a verbatim
// Authorization header and falls back to the gateway's forwarded access token
// (adding the Bearer scheme oauth2-proxy strips). Empty when the request
// carries no credential — the downstream service then refuses it, which is
// the honest outcome.
func ForwardAuthorization(h Headers) string {
	if a := strings.TrimSpace(h.Get(HeaderAuthorization)); a != "" {
		return a
	}

	if t := strings.TrimSpace(h.Get(HeaderAccessToken)); t != "" {
		return "Bearer " + t
	}

	return ""
}

// HeaderGetter adapts a plain header-lookup function (http.Header.Get,
// connect req.Header().Get) to the Headers interface.
type HeaderGetter func(name string) string

// Get satisfies Headers.
func (g HeaderGetter) Get(name string) string { return g(name) }
