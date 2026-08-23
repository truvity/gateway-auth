# gateway-auth — the rules

The authoritative reference for browser authentication across the fleet. This
supersedes the OIDC section of the gitops **expose-a-ui** guide ("Browser UI
behind gateway OIDC"): where that guide describes the per-app Envoy `oidc`
SecurityPolicy block, use the shape below instead. The `oidc` block remains
documented there only as the pre-`gateway-auth` fallback.

## The model

Browser login happens **at the gateway, never in the app**. oauth2-proxy sits
in front of the internal Envoy Gateway as an HTTP `ext_authz` backend: it runs
the OIDC authorization-code flow, keeps the token set in Valkey, and hands the
browser only a small session ticket cookie. On every request Envoy calls
oauth2-proxy; an authenticated request is allowed and its access token is
copied onto the request as `X-Auth-Request-Access-Token`. The SecurityPolicy's
`jwt` + `authorization` rules then deny anyone outside the route's groups
before the request ever reaches the backend.

What is left for the application is the part a gateway cannot do on its behalf:
knowing **who** the caller is and **which of the application's own roles** they
hold, because that changes which handlers refuse. The Go and TS libraries do
exactly that and no more — they consume a verified identity; they never run a
code flow, hold client credentials, or mint sessions.

Two structural rules follow from "the gateway is the OIDC client":

- **One oauth2-proxy per OIDC client.** A proxy is a single confidential
  client with a single redirect set and one cookie/session domain. Sharing one
  proxy across unrelated products would mean sharing one client — collapsing
  their identities.
  - The **platform proxy** uses the shared cluster-project client
    `gateway-auth-oidc` (Platform org, `cluster-{env}` project) and fronts
    **hubble + gemaal + roster**. These are cluster-admin surfaces authorized
    by cluster-spine roles, so one client is correct.
  - **url-shortener** and **eudi** each run **their own proxy** with **their
    own product-project client**. This is what preserves INF-436: each
    business app keeps its per-product-project `OIDCApp` (its own org/project),
    and a dedicated proxy per client is the only way to keep those identities
    separate.
- **Per-install Valkey.** Each proxy owns its own `ValkeyCluster` (session
  store); a session leak or restart in one product never touches another. The
  Valkey **operator** runs fleet-wide (it is no longer role-gated to devel);
  the per-cluster `gateway-auth` role is retired.

## Two trust models

The forwarded token can be *verified* by the service or *trusted* from the
proxy's headers. Pick per surface; the default is verify.

### verify-in-app (default) — JWKS

The service re-verifies the forwarded access token against the issuer's JWKS
(discovery → signature, issuer, audience, expiry). Not because the gateway is
untrustworthy, but because "we are only reachable through the gateway" is a
property of a NetworkPolicy — one YAML file away from being wrong — and a
service that can mutate real state should not rest its authorization on that.
Use this everywhere by default; it is the only correct choice for any service
that writes.

In Go this is `OAuth2ProxyOIDC(...)` / `NewVerifier(...)`. The keyset refreshes
in the background (15 min) and a refresh failure keeps the previous keys rather
than locking everyone out.

### trust-gateway-headers (opt-in) — no verification

The service builds the identity from oauth2-proxy's pre-parsed headers
(`X-Auth-Request-User` / `-Email` / `-Groups`, and `-Access-Token` for
downstream calls) **without verifying a token**. Faster and dependency-free,
but only sound where the **ingress-from-fleet NetworkPolicy is genuinely the
trust boundary** — an airtight netpol so that nothing but the gateway can reach
the service. It is opt-in, never a fallback from a misconfiguration, and it
still requires the headers to be present, so a request that bypassed the proxy
is rejected (`ErrNoCredential`), not admitted anonymously.

In Go this is `gatewayauth.NewHeaderTrust()`. It satisfies the same
`Authenticator` interface, so the adapters below are written once and work with
either model.

> Local development only: `gatewayauth.NewDisabled(roles...)` authorizes
> everybody as the given roles. Its `Enabled()` returns `false`, which makes
> the adapters skip role checks — pass the operator-level role so dev matches
> production's most-privileged path. Never reachable except by explicit opt-in.

## How to expose a UI

Include the `gateway-auth` chart (library chart `gateway-auth.exposure` for
chart-based consumers — roster, url-shortener-infra, eudi-infra; the gitops
gateways stack renders hubble/gemaal/the shared platform proxy through the same
templates). Set the knobs; the chart emits the whole chain: `OIDCApp`
(project-aware) → `/{prefix}/*` HTTPRoute → the oauth2-proxy install
(Deployment/Service/ValkeyCluster/ESO cookie Secret/ConfigMap) → the `extAuth`
SecurityPolicy with `jwt` authorization → the ingress-from-fleet NetworkPolicy.

Knobs (`exposure.*`):

| Knob | Meaning |
| --- | --- |
| `enabled` | Render the exposure. |
| `hostname` | Public host, e.g. `roster.{gatewaySuffix}`. |
| `gateway` | Name of the per-component `Gateway` (class `internal`). |
| `issuer` | OIDC issuer URL (the Zitadel domain). |
| `proxyPrefix` | Path the proxy's own endpoints live under. Default `/oauth2`; override to avoid a collision (eudi ↔ Hydra). |
| `identity.project` | `cluster` — the shared Platform org `cluster-{env}` project (`platformZitadelProjectId`). Attaches to the **shared platform proxy**; no own proxy/Valkey. |
| `identity.projectRef` | Name of the install's own `Project` CR (`zitadel-operator-truvity`). Provisions a **dedicated proxy + Valkey** for a product-project client. Mutually exclusive with `identity.project`. |
| `passAuthorizationHeader` | Also set the downstream `Authorization: Bearer` header (`set_authorization_header=true` on this proxy). Off by default; per-install, zero blast radius. |
| `routes[]` | Per-route protection list. Each entry is a path prefix and whether it is protected; unlisted-as-anonymous routes bypass the SecurityPolicy. Omit for the simple "protect everything under `/`" case. |
| `routes[].authenticatedOnly` | ext_authz is the whole gate — any org user who logs in passes and the token is still forwarded, but NO jwt/`groups` block is emitted (the app authorizes itself). The business-app posture; `authorization.groups` is then not required for the route. Omit it for platform UIs that gate on `groups`. |
| `routes[].targetRouteName` | **Attach mode** — bind the SecurityPolicy to an **existing** `HTTPRoute` (owned elsewhere, e.g. a ring3 app chart) instead of creating one. The chart then renders no app route/backend for that entry (only the SecurityPolicy); the `{proxyPrefix}` proxy route stays chart-owned. Use it when the app chart already owns the route (the business-app ring2/ring3 split); omit it for platform UIs where this chart owns the route. |
| `authorization.groups` | The `groups` claim values that are allowed (any-of). `defaultAction` is Deny — "authenticated" is never sufficient. |
| `backend` | The UI's Service (name + port) in the same namespace. Not needed for `targetRouteName` (attach) routes. |

### (a) A simple platform UI on the shared cluster project

roster: shares the platform client + proxy, protects everything, authorizes on
cluster-spine roles.

```yaml
exposure:
  enabled: true
  hostname: roster.{{ .Values.gatewaySuffix }}
  gateway: roster
  issuer: https://{{ .Values.zitadelDomain }}
  identity:
    project: cluster            # gateway-auth-oidc on cluster-{env}; shared platform proxy
  authorization:
    groups:
      - "cluster-{{ .Values.clusterName }}:roster:operator"
      - "cluster-{{ .Values.clusterName }}:roster:viewer"
  backend:
    service: roster
    port: 80
```

### (b) A business app: own product project, Authorization header

url-shortener: its own product-project client → **its own proxy + Valkey**; its
`/api/me` reads the bearer token from the `Authorization` header, so the proxy
must also set it.

```yaml
exposure:
  enabled: true
  hostname: url-shortener.{{ .Values.gatewaySuffix }}
  gateway: url-shortener
  issuer: https://{{ .Values.zitadelDomain }}
  identity:
    projectRef: url-shortener   # product-project OIDCApp (INF-436); dedicated proxy
  passAuthorizationHeader: true # /api/me consumes Authorization: Bearer
  authorization:
    groups:
      - "url-shortener:app:user"
  backend:
    service: url-shortener-web
    port: 3000
```

### (c) A business app on a Hydra-shared host: custom prefix, per-route list

eudi: its host also serves Ory Hydra's `/oauth2` endpoints, so the proxy's own
endpoints move to `/_gwauth`. Only the demo/admin surface is protected; the
wallet, issuer, and Hydra routes stay anonymous. This replaces the old
route-scoped-callback hack.

```yaml
exposure:
  enabled: true
  hostname: eudi.{{ .Values.gatewaySuffix }}
  gateway: eudi
  issuer: https://{{ .Values.zitadelDomain }}
  proxyPrefix: /_gwauth         # keep /oauth2 free for Hydra
  identity:
    projectRef: eudi            # product-project OIDCApp (INF-436); dedicated proxy
  routes:
    - path: /admin              # protected
      protected: true
    - path: /wallet             # anonymous — verifiable-credential wallet API
      protected: false
    - path: /issuer             # anonymous — credential issuance
      protected: false
    - path: /oauth2             # anonymous — Ory Hydra
      protected: false
  authorization:
    groups:
      - "eudi:app:admin"
  backend:
    service: eudi-web
    port: 3000
```

## How to consume identity — Go

Import `gatewayauth "github.com/truvity/gateway-auth"` for the core and the
adapter for your framework. Build one `Authenticator` at startup:

```go
auth, err := gatewayauth.OAuth2ProxyOIDC(ctx, logger, issuer) // verify-in-app
// or gatewayauth.NewHeaderTrust()                            // trust-gateway-headers
// or gatewayauth.NewDisabled("...:operator")                 // local dev only
```

`Identity` carries `Subject`, `Name`, `Email`, `Roles` (the raw `groups`
values, e.g. `"cluster-kernel:roster:operator"`), `Token` (the verified access
token, for calling a downstream API as the caller), and `Claims` (every claim,
for app-specific reads). Helpers: `id.HasRole(r)`, `id.HasAnyRole(a, b)`.

**fiber v3** (`adapters/fibermw`):

```go
app.Use("/api", fibermw.Require(auth))                    // 401 without a valid credential
app.Get("/public", fibermw.Optional(auth), h)            // attach if present, else anonymous
app.Post("/admin", fibermw.RequireRoles(auth, "..."), h) // 401, then 403 without a role
id, ok := fibermw.From(c)                                // read it in a handler
```

`RequireRoles` skips the role check when the authenticator is disabled (local
dev). `Optional` is for a process serving protected and public routes together
(eudi's demo alongside its wallet/issuer surfaces).

**huma v2** (`adapters/humamw`) — a registered security scheme, so the
requirement appears in the generated OpenAPI. Call `humamw.Register(api, auth)`
once after `huma.New`, then declare per operation; the scheme's scopes are the
roles the operation requires (any-of):

```go
humamw.Register(api, auth)

huma.Register(api, huma.Operation{
	OperationID: "sync",
	Method:      http.MethodPost,
	Path:        "/sync",
	Security:    []map[string][]string{{humamw.SchemeName: {"cluster-kernel:roster:operator"}}},
}, handler)
```

An operation with no `humamw.SchemeName` entry is left anonymous. Read the
identity in the handler with `gatewayauth.FromContext(ctx)`.

**connectrpc** (`adapters/connectmw`) — a unary interceptor. connect carries no
per-procedure security metadata, so the interceptor authenticates and attaches
the identity; handlers enforce their own roles:

```go
interceptors := connect.WithInterceptors(connectmw.Interceptor(auth))
// or connectmw.OptionalInterceptor(auth)

func (s *Server) Sync(ctx context.Context, req *connect.Request[...]) (...) {
	id, _ := gatewayauth.FromContext(ctx)
	if !id.HasRole("...:operator") {
		return nil, connect.NewError(connect.CodePermissionDenied, ...)
	}
}
```

### userinfo fallback (name/email, e.g. `/api/me`)

Zitadel asserts profile claims (`name`, `email`) into the **ID token**, not the
access token, so an access-token-only identity can arrive with an empty
`Name`/`Email` — which a `/api/me`-style endpoint needs. The verifier's
`UserinfoFallback` fills them from the issuer's userinfo endpoint, using the
caller's own already-verified token, cached per subject (1 h). It only ever
degrades display — a userinfo failure never fails the request. The
`OAuth2ProxyOIDC` preset turns it on; with a hand-built `Config` set
`UserinfoFallback: true`. This is orthogonal to the proxy's
`passAuthorizationHeader` — that decides which header carries the token,
`UserinfoFallback` decides whether missing display claims are backfilled.

## How to consume identity — TS

The node web tiers (url-shortener, eudi) use `@truvity/gateway-auth` — the same
core over `jose` remote JWKS. Its middleware verifies the forwarded access
token against the issuer, attaches the identity to the request, and exposes the
same two-model choice (verify vs trust-headers). Use it wherever the node tier
needs the caller — the `/api/me` handler and any role-gated route — instead of
re-implementing verification. (The package is part of v1; see `ts/`.)

## Migration

This replaces the per-app Envoy `oidc` SecurityPolicy blocks. For each existing
exposure: swap the `oidc` block for the `gateway-auth` chart's `extAuth`
SecurityPolicy (pointing at that install's proxy), drop the per-host `OIDCApp`
where a shared client now covers it (hubble-oidc, gemaal-oidc fold into
`gateway-auth-oidc`), and — for a service that reads the identity — adopt the Go
or TS library in place of any hand-rolled header parsing. The `jwt` provider
and `authorization` rules are unchanged in intent; they now read the token from
`X-Auth-Request-Access-Token` (via `jwt.providers[].extractFrom`).

Out of scope by design, do not migrate:

- **headlamp** — authenticates in-app with OIDC PKCE (`usePKCE: true`), not at
  the gateway.
- **argocd** — has its own `oidc.config`.

## Why not X

- **Why not trust the headers everywhere?** Because then authorization rests
  entirely on the ingress NetworkPolicy being airtight — one edit away from
  admitting any pod in the cluster as any user. Verify-in-app costs a JWKS
  cache and survives a wrong netpol. Trust-headers is reserved for surfaces
  where the netpol genuinely *is* the boundary and is treated as such.
- **Why not one shared proxy for everything?** A proxy is one OIDC client. One
  client for all products would collapse their identities and break INF-436's
  per-product-project separation, and one Valkey/one cookie domain would couple
  their session blast radius. Platform admin surfaces legitimately share a
  client (one cluster-spine identity), so they share the platform proxy;
  every business product gets its own client, proxy, and Valkey.
