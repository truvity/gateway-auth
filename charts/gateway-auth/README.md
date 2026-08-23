# gateway-auth

Browser-auth exposure for a UI in the **"oauth2-proxy shape"** (INF-562), so
no app hand-rolls an Envoy `SecurityPolicy`. One `oauth2-proxy` per OIDC
client, **per-install Valkey** session storage, and — per protected route —
an Envoy `extAuth` `SecurityPolicy` doing HTTP `ext_authz` to the proxy plus
`jwt` groups authorization.

The recipe is lifted field-for-field from the gitops gateways stack
(`stacks/gateways/templates/oauth2-proxy.yaml` + `retina-gateway.yaml`) and
generalized into per-install knobs. It replaces the per-app
`OIDCApp`+`SecurityPolicy` that `url-shortener-infra` and `eudi-infra`
currently hand-roll (`templates/exposure.yaml` in each).

## What it emits (guarded by `exposure.enabled`)

Per install:

- `OIDCApp` (`zitadel.truvity.io/v1alpha2`) — confidential JWT client;
  `redirectUris = https://{hostname}{proxyPrefix}/callback`, post-logout the
  root ±`/`. Binds to a **shared cluster project** (`projectId`) or an
  **install product Project CR** (`projectRef`).
- `ValkeyCluster` (`valkey.io/v1alpha1`) — this install's own session store.
  The operator owns the pods + the headless Service
  `valkey-{name}-sessions:6379`; the chart makes **no** Service/Secret for it.
- `Password` + `ExternalSecret` (ESO) — the AES-256 cookie secret, generated
  in-cluster (`CreatedOnce`).
- `oauth2-proxy` `Service` + `Deployment` + `ConfigMap` — `provider = oidc`,
  `reverse_proxy`, `upstreams = ["static://200"]`, `set_xauthrequest`,
  `pass_access_token`, Redis session store pointed at this install's Valkey,
  `proxy_prefix = {proxyPrefix}`, and `set_authorization_header` from
  `exposure.passAuthorizationHeader`. A `checksum/config` annotation rolls
  the pods on config change.

Per route (`exposure.routes`):

- an `HTTPRoute` to the route's backend Service; plus one `HTTPRoute` for
  `{proxyPrefix}/` → `oauth2-proxy:4180` carrying **no** `SecurityPolicy`
  (the code flow must be reachable unauthenticated);
- for **protected** routes, an `extAuth` `SecurityPolicy`
  (`gateway.envoyproxy.io/v1alpha1`) with `headersToExtAuth`
  (`cookie`, `x-forwarded-*`), `headersToBackend` (`x-auth-request-*`), a
  `jwt` provider (`remoteJWKS` + `extractFrom X-Auth-Request-Access-Token`),
  and `authorization` `defaultAction: Deny` + a groups `Allow` rule.

Unlisted / anonymous routes (eudi wallet/issuer/Hydra) get **no**
`SecurityPolicy` — anonymous by construction.

Optionally: an ingress-from-fleet `NetworkPolicy` admitting the shared Envoy
data-plane to the proxy's ext_authz port (`exposure.networkPolicy`).

## Two ways to use it

### 1. Standalone / app chart

Render it directly from its own `values.yaml` — `templates/exposure.yaml`
calls the reusable template. This is how gitops renders hubble / gemaal / the
shared platform proxy:

```console
helm template hubble ./charts/gateway-auth -f hubble-values.yaml -n kube-system
```

### 2. Library (as a dependency of another chart)

Add it as a dependency and `include` the named template from your own
templates, passing your root context (`.`). Your chart's `.Values.exposure`
(and `.Values.clusterName`) then drive it:

```yaml
# Chart.yaml
dependencies:
  - name: gateway-auth
    version: "0.1.0"
    repository: "file://../gateway-auth"
```

```yaml
# templates/exposure.yaml (in the consumer chart)
{{ include "gateway-auth.exposure" . }}
```

> The chart is `type: application`, **not** `library`: a library chart
> renders none of its own templates, which would break usage mode 1. Making
> it an application chart that *also* exposes `include`-able named templates
> (in `templates/_exposure.tpl` / `_helpers.tpl`) gives both modes at once.

The reusable named templates are:

| template | purpose |
| --- | --- |
| `gateway-auth.exposure` | the whole shape (call this) |
| `gateway-auth.oauth2ProxyCfg` | the proxy config body (shared by the ConfigMap and the pod checksum) |
| `gateway-auth.name` / `.proxyName` / `.valkeyName` / `.valkeyHost` / `.oidcSecretName` / `.cookieName` | derived names |
| `gateway-auth.labels` / `.proxySelectorLabels` / `.resourceAnnotations` | labels + sync-wave annotations |

## Key values

See `values.yaml` for the full set and `values.schema.json` for the strict
(draft-07) contract. The load-bearing knobs:

| value | meaning |
| --- | --- |
| `exposure.enabled` | master switch |
| `exposure.name` | base name for all resources (default: release name) |
| `exposure.hostname` | public host (required) |
| `exposure.issuer` | OIDC issuer, e.g. `https://auth.truvity.xyz` (required) |
| `exposure.proxyPrefix` | path the proxy owns (default `/oauth2`; eudi `/_gwauth`) |
| `exposure.gateway.{name,namespace,sectionName}` | parent Gateway/listener |
| `exposure.identity.project.cluster` + `.projectId` | shared cluster project by id |
| `exposure.identity.project.ref` | install product `Project` CR (projectRef) |
| `exposure.passAuthorizationHeader` | also send `Authorization: Bearer` (url-shortener `/api/me`) |
| `exposure.routes[]` | `{name, path, pathType, protected, backend}` |
| `exposure.authorization.groups[]` | jwt groups Allow-list (required for any protected route) |
| `exposure.backend.{name,port}` | default protected-route backend Service |
| `exposure.proxy.*` | image, replicas, resources, scheduling |
| `exposure.valkey.*` | shards/replicas/persistence/… |
| `exposure.networkPolicy.*` | ingress-from-fleet toggle + port |

## Deviations from the reference shapes

- **Per-install proxy selector.** The gateways-stack proxy selects on
  `app.kubernetes.io/name: oauth2-proxy` alone (one shared proxy).
  `gateway-auth.proxySelectorLabels` adds `app.kubernetes.io/instance` so two
  installs' proxies in one namespace don't cross-select.
- **Per-install Valkey.** The reference ValkeyCluster is `gateway-sessions`
  in `kube-system`; here each exposure gets its own `{name}-sessions` and its
  own Redis URL (the agreed design).
- **`cookie_domains`/`whitelist_domains` default to the single host** rather
  than the shared `.{gatewaySuffix}` parent. Set `exposure.cookieDomains` to
  a leading-dot parent to restore cross-subdomain sharing.
- **Image is a plain `repository:tag`** knob (default
  `quay.io/oauth2-proxy/oauth2-proxy`), not the ECR-composed
  `{accountID}.dkr.ecr…` string — gitops overrides `exposure.proxy.image.repository`
  with the cluster's ECR mirror.
- **Scheduling is parametrized, not hardcoded.** The reference pins arm64
  (`nodeSelector` + tolerations + topologySpread); here those are empty
  passthroughs (`exposure.proxy.{nodeSelector,tolerations,topologySpreadConstraints}`).
- **Fails closed on empty groups.** A protected route with no
  `authorization.groups` would render an invalid empty `values:` list; the
  template fails the render instead.
