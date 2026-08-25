// Sign-out URL for a gateway-auth exposure. The oauth2-proxy owns
// `${proxyPrefix}/sign_out`, which clears the session cookie; the next request
// re-runs the OIDC login. proxyPrefix defaults to "/oauth2" and is overridden
// per install (eudi shares its host with Hydra and uses "/_gwauth").
/**
 * signOutUrl builds the oauth2-proxy sign-out URL. Pass the exposure's
 * proxyPrefix (default "/oauth2"); an optional redirectTo becomes the proxy's
 * `rd` parameter, honored when its domain is in the proxy's allow-list.
 */
export function signOutUrl(proxyPrefix = "/oauth2", redirectTo) {
    const prefix = proxyPrefix.startsWith("/") ? proxyPrefix : `/${proxyPrefix}`;
    const base = `${prefix.replace(/\/+$/, "")}/sign_out`;
    return redirectTo ? `${base}?rd=${encodeURIComponent(redirectTo)}` : base;
}
//# sourceMappingURL=signout.js.map