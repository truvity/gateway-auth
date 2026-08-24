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
