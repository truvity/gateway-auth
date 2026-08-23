# gateway-auth

One browser-auth shape for the fleet. Login happens at the internal gateway —
[oauth2-proxy] as an Envoy Gateway HTTP `ext_authz` backend runs the OIDC
authorization-code flow and holds the token set in [Valkey]; the browser keeps
only a small session ticket. The gateway forwards the caller's access token to
the service as `X-Auth-Request-Access-Token`, and the service turns that into a
verified identity. No application runs a code flow of its own.

This shape supersedes the per-app hand-rolled Envoy `oidc` SecurityPolicy
blocks (INF-504 cookie-cap failures, INF-562). The rules — the authoritative
reference — are in [docs/gateway-auth.md](docs/gateway-auth.md).

## Three artifacts, versioned together

| Artifact | Path | What it does |
| --- | --- | --- |
| **Helm chart** | [`charts/gateway-auth`](charts/gateway-auth) | Exposes a UI: OIDCApp → `/{prefix}/*` HTTPRoute → oauth2-proxy (Deployment/Service/ValkeyCluster/ESO cookie/ConfigMap) → `extAuth` SecurityPolicy + jwt authorization + ingress-from-fleet NetworkPolicy. |
| **Go module** `github.com/truvity/gateway-auth` | repo root + [`adapters/`](adapters) | Turns a forwarded token into a verified `Identity`. Core (JWKS verify, OIDC discovery, configurable claims) plus fiber v3 / huma v2 / connectrpc adapters. |
| **TS package** `@truvity/gateway-auth` | [`ts/`](ts) | Same core (jose remote JWKS) for the node web tiers (url-shortener, eudi). |

## Go quickstart

```go
import (
	gatewayauth "github.com/truvity/gateway-auth"
	"github.com/truvity/gateway-auth/adapters/fibermw"
)

// At startup: discover the issuer, fetch its JWKS. An unreachable issuer
// fails here, not on the first request.
auth, err := gatewayauth.OAuth2ProxyOIDC(ctx, logger, "https://<zitadel-issuer>")
if err != nil {
	return err
}

// Guard a route: authenticate, then require one of the app's roles.
app.Get("/admin", fibermw.RequireRoles(auth, "cluster-kernel:roster:operator"), handler)

// Read the caller inside a handler.
func handler(c fiber.Ctx) error {
	id, _ := fibermw.From(c)
	return c.JSON(fiber.Map{"subject": id.Subject, "roles": id.Roles})
}
```

`OAuth2ProxyOIDC` is the opinionated preset (Zitadel + oauth2-proxy, `groups`
claim → roles, userinfo fallback for display names). Every seam is still
overridable through `gatewayauth.NewVerifier(gatewayauth.Config{...})`.

## Layout

```
charts/gateway-auth/     Helm chart (exposure)
docs/gateway-auth.md     the rules — start here
*.go                     Go core (package gatewayauth)
adapters/fibermw/        fiber v3 middleware
adapters/humamw/         huma v2 security scheme + middleware
adapters/connectmw/      connectrpc interceptor
ts/                      @truvity/gateway-auth (node web tiers)
```

## Scope

In: hubble, gemaal, roster (platform UIs, shared cluster-project client) and
url-shortener, eudi (business apps, own product-project client). Out by
design: **headlamp** (in-app OIDC with PKCE) and **argocd** (own
`oidc.config`) — neither authenticates at the gateway.

[oauth2-proxy]: https://oauth2-proxy.github.io/oauth2-proxy/
[Valkey]: https://valkey.io/
