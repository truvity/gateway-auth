package gatewayauth

import (
	"net/url"
	"strings"
)

// SignOutURL builds the oauth2-proxy sign-out URL for a gateway-auth exposure.
// The proxy owns "<proxyPrefix>/sign_out", which clears the session cookie so
// the next request re-runs the OIDC login. proxyPrefix defaults to "/oauth2"
// when empty and is overridden per install (eudi shares its host with Hydra
// and uses "/_gwauth"). A non-empty redirectTo becomes the proxy's "rd"
// parameter, honored when its domain is in the proxy's allow-list.
//
// This is a LOCAL sign-out and that is all it can be. It clears this
// proxy's cookie and its stored session; it does not end the session at the
// identity provider, because oauth2-proxy cannot unless that provider
// implements RP-Initiated Logout.
//
// So the user-visible behaviour is the provider's, not ours:
//
//   - with an end_session_endpoint in its discovery document, the provider
//     can be sent a redirect that ends its session too, and sign-out works
//     the way people expect;
//   - without one, the next request 302s straight back through the provider
//     and the user is silently signed in again. dex is in this category: it
//     advertises no end_session_endpoint and re-runs its connector on every
//     authorize, so the session that survives is the UPSTREAM provider's.
//
// Check the provider's discovery document before putting this behind a
// button labelled "log out", or it will appear to do nothing.
func SignOutURL(proxyPrefix, redirectTo string) string {
	if proxyPrefix == "" {
		proxyPrefix = "/oauth2"
	}

	if !strings.HasPrefix(proxyPrefix, "/") {
		proxyPrefix = "/" + proxyPrefix
	}

	base := strings.TrimRight(proxyPrefix, "/") + "/sign_out"

	if redirectTo == "" {
		return base
	}

	return base + "?rd=" + url.QueryEscape(redirectTo)
}
