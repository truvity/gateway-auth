{{- /* ==========================================================================
   gateway-auth.oauth2ProxyCfg — the oauth2-proxy config body, defined once so
   the ConfigMap and the Deployment's checksum/config annotation share it: a
   config change then rolls the pods (oauth2-proxy reads its config only at
   startup). Copied field-for-field from the gitops gateways-stack reference
   (stacks/gateways/templates/oauth2-proxy.yaml), with the shared-proxy
   constants turned into per-install knobs (host, issuer, proxy_prefix, redis
   URL, set_authorization_header).
   ========================================================================== */ -}}
{{- define "gateway-auth.oauth2ProxyCfg" -}}
{{- $e := .Values.exposure -}}
{{- $hostname := required "exposure.hostname is required when exposure.enabled" $e.hostname -}}
{{- $issuer := required "exposure.issuer is required when exposure.enabled" $e.issuer -}}
{{- $proxyPrefix := $e.proxyPrefix | default "/oauth2" -}}
{{- $cookieDomains := $e.cookieDomains | default (list $hostname) -}}
provider = "oidc"
oidc_issuer_url = "{{ $issuer }}"
redirect_url = "https://{{ $hostname }}{{ $proxyPrefix }}/callback"
# The path prefix this proxy owns (sign_in, start, callback, sign-out). Must
# agree with the HTTPRoute that routes {{ $proxyPrefix }}/ to the proxy and
# with the OIDCApp redirectUri above.
proxy_prefix = "{{ $proxyPrefix }}"

http_address = "0.0.0.0:4180"
reverse_proxy = true
# static://200 (not 202): Envoy's ext_authz treats ONLY a 200 from the auth
# service as "allow" and forwards the original request to the real backend;
# any other status (202 included) is a deny, and the auth response body is
# returned to the browser (INF-562).
upstreams = ["static://200"]

# Cookie/redirect domain allow-list. Per-install default is the single
# exposure host; set exposure.cookieDomains to a leading-dot parent
# (e.g. ".devel.truvity.xyz") to share one session cookie across subdomains.
cookie_domains = [{{ range $i, $d := $cookieDomains }}{{ if $i }}, {{ end }}"{{ $d }}"{{ end }}]
whitelist_domains = [{{ range $i, $d := $cookieDomains }}{{ if $i }}, {{ end }}"{{ $d }}"{{ end }}]
cookie_secure = true
cookie_samesite = "lax"
# Session lifetime. The default ALIGNS UNDER the access token's (Zitadel
# default 12h, minted at the same login that starts this session), because
# without refresh a session outliving its token strands the user on Envoy's
# raw "Jwt is expired" 401 until the cookie dies — days, at oauth2-proxy's
# 168h default (observed on roster.kernel, 2026-08-27). With the session
# expiring FIRST, the next request 302s through the provider instead:
# silent when the provider's own session is still alive, a login prompt
# when not. The 1h margin keeps the boundary race on the session side.
#
# session.refresh lifts that ceiling. oauth2-proxy then renews the access
# token once the cookie is older than the refresh interval, so expire no
# longer has to hide under the token lifetime. Two conditions, and BOTH
# fail silently rather than loudly:
#
#   - refresh MUST be shorter than expire. Set the other way round the
#     cookie dies before a refresh is ever attempted, and the config looks
#     correct while behaving exactly as if refresh were unset.
#   - the provider must actually issue a refresh token, which needs the
#     offline_access scope. The scope block above adds it whenever
#     session.refresh is set. Setting identity.scopes by hand overrides
#     that, so the two together are REFUSED at render time unless the
#     explicit list includes offline_access itself.
cookie_expire = {{ ($e.session | default dict).expire | default "11h" | quote }}
{{- with ($e.session | default dict).refresh }}
cookie_refresh = {{ . | quote }}
{{- end }}
# Per-request CSRF cookie, keyed to the OAuth state (INF-562). A page load
# fires several unauthenticated requests at once; with one shared CSRF
# cookie the last writer's PKCE code_verifier clobbers the others and the
# callback fails token exchange (invalid_grant). A per-request cookie gives
# each flow its own verifier.
cookie_csrf_per_request = true
cookie_csrf_expire = "5m"

{{- /*
     SCOPES. oauth2-proxy only receives a claim the provider was ASKED for,
     and the jwt/groups authorization rule further down reads `groups` out
     of the access token oauth2-proxy forwards. So a protected route with
     an authorization.groups allow-list needs the groups scope requested
     here, or the provider returns a token with no groups claim, the rule
     matches nothing, and defaultAction Deny rejects every request from
     every user -- a total outage that looks like a policy typo.

     Zitadel hid this: it asserts role claims because the OIDCApp says so,
     not because a scope was requested, so the allow-list worked without
     the scope. A standards-compliant provider (dex, Keycloak, Auth0,
     Entra) does not, and omits the claim entirely when the list is empty.

     Requesting it unconditionally would be the simpler code and the wrong
     behaviour: `groups` on a large directory can inflate the token past
     the 4KB cookie chunk that oauth2-proxy splits sessions on, for
     installs that never authorize on groups at all. So it is added only
     when an allow-list is actually configured.
*/ -}}
{{- $scopes := $e.identity.scopes -}}
{{- if not $scopes -}}
{{- $scopes = "openid profile email" -}}
{{- if $e.authorization.groups -}}
{{- $scopes = printf "%s groups" $scopes -}}
{{- end -}}
{{- if ($e.session | default dict).refresh -}}
{{- $scopes = printf "%s offline_access" $scopes -}}
{{- end -}}
{{- else if and ($e.session | default dict).refresh (not (contains "offline_access" $scopes)) -}}
{{- /* An explicit scope list overrides the offline_access this chart would
   have added, and without it the provider issues no refresh token: the
   install renders cleanly, cookie_refresh is present, and oauth2-proxy
   simply never refreshes. Fail instead -- there is no reading of these
   two values together that the author could have meant. */ -}}
{{- fail "exposure.identity.scopes is set alongside exposure.session.refresh but omits offline_access; refresh cannot work without a refresh token, so add offline_access to the scope list or unset one of the two" -}}
{{- end }}
scope = {{ $scopes | quote }}
code_challenge_method = "S256"
skip_provider_button = true

# Authorization is the gateway's job (jwt groups rules), not oauth2-proxy's:
# accept any authenticated org user here.
email_domains = ["*"]

# Hand the access token downstream for the jwt filter to validate.
set_xauthrequest = true
pass_access_token = true
{{- if $e.passAuthorizationHeader }}
# exposure.passAuthorizationHeader: also forward the token in the standard
# Authorization: Bearer header (url-shortener /api/me resolves it at the
# Zitadel userinfo endpoint, in addition to X-Auth-Request-Access-Token).
set_authorization_header = true
{{- else }}
set_authorization_header = false
{{- end }}

# Session state in this install's own Valkey (cluster-aware even at one shard).
session_store_type = "redis"
redis_use_cluster = true
{{- if ($e.sessionStore | default dict).url }}
redis_connection_url = "{{ $e.sessionStore.url }}"
{{- else }}
redis_cluster_connection_urls = ["redis://{{ include "gateway-auth.valkeyHost" . }}.{{ .Release.Namespace }}.svc.{{ include "gateway-auth.dnsDomain" . }}:6379"]
{{- end }}
{{- end -}}


{{- /* ==========================================================================
   gateway-auth.exposure — the full "oauth2-proxy shape" for one UI, guarded
   by exposure.enabled. Emits (per install): OIDCApp, ValkeyCluster, ESO
   Password + ExternalSecret cookie, oauth2-proxy Service/Deployment/ConfigMap,
   the {proxyPrefix} HTTPRoute to the proxy (no SecurityPolicy), and — per
   route — an HTTPRoute plus (for protected routes) an extAuth SecurityPolicy;
   plus the ingress-from-fleet NetworkPolicy when enabled.
   ========================================================================== */ -}}
{{- define "gateway-auth.exposure" -}}
{{- if .Values.exposure.enabled -}}
{{- $root := . -}}
{{- $e := .Values.exposure -}}
{{- $name := include "gateway-auth.name" . -}}
{{- $hostname := required "exposure.hostname is required when exposure.enabled" $e.hostname -}}
{{- $issuer := required "exposure.issuer is required when exposure.enabled" $e.issuer -}}
{{- $proxyPrefix := $e.proxyPrefix | default "/oauth2" -}}
{{- $gw := required "exposure.gateway is required when exposure.enabled" $e.gateway -}}
{{- $routes := $e.routes | default (list (dict "name" "app" "path" "/" "protected" true)) -}}
{{- if not $routes -}}
{{- fail "exposure.routes must list at least one route when exposure.enabled" -}}
{{- end -}}
{{- /* Fail closed on the misconfiguration that renders an INVALID policy:
   a protected route with no groups allow-list produces a claim with an
   empty `values:` list (defaultAction Deny + zero Allow = nobody, which
   the CRD rejects and which is never intended). */ -}}
{{- range $route := $routes -}}
{{- if and $route.protected (not $route.authenticatedOnly) (not $e.authorization.groups) -}}
{{- fail (printf "exposure.authorization.groups must be non-empty: route %q is protected (or set the route authenticatedOnly: true for the ext_authz-only, app-authorizes posture)" $route.name) -}}
{{- end -}}
{{- end -}}
# ==========================================================================
# gateway-auth exposure for {{ $hostname }} (install {{ $name }}).
# The "oauth2-proxy shape" (INF-562): one oauth2-proxy per OIDC client with
# per-install Valkey sessions, called by Envoy as HTTP ext_authz, and jwt
# groups authorization on top. Recipe source: gitops stacks/gateways/
# templates/{oauth2-proxy,retina-gateway}.yaml.
# ==========================================================================
{{- /* The OIDCApp is Zitadel-specific: it asks that operator to create an
   app and mint the client Secret. In "static" identity mode there is no
   operator to ask -- the caller registered the client with whatever
   provider they run and handed us the Secret -- so this whole document
   is skipped. Nothing downstream changes; only the SOURCE of the
   credential does. */ -}}
{{- if ne (default "zitadel" $e.identity.mode) "static" }}
---
# OIDC client for THIS install's oauth2-proxy, minted by the Zitadel
# operator. Token shape matches hubble (retina-gateway.yaml): the gateway's
# authorization reads the mapper's flat `groups` claim from the ACCESS
# token, so it must be a JWT; native urn:zitadel role assertions stay OFF
# (INF-504 — the ~1KB blob that broke the cookie).
apiVersion: zitadel.truvity.io/v1alpha2
kind: OIDCApp
metadata:
  name: {{ $name }}-oidc
  annotations:
    {{- include "gateway-auth.resourceAnnotations" (dict "root" $root "wave" "10") | nindent 4 }}
  labels:
    {{- include "gateway-auth.labels" $root | nindent 4 }}
spec:
  name: {{ $e.identity.appName | default (printf "%s-%s" $name $root.Values.clusterName) }}
{{- if $e.identity.project.cluster }}
  # Shared cluster project, referenced by projectId (the gateways-stack
  # shape — platform's cluster-{env} project).
  projectId: {{ required "exposure.identity.projectId is required when exposure.identity.project.cluster" $e.identity.projectId | quote }}
{{- else }}
  # v0.19 projectRef → an install's own product Project CR (the
  # url-shortener-infra / eudi-infra shape, INF-436 un-conflation).
  projectRef:
    name: {{ required "exposure.identity.project.ref is required when not exposure.identity.project.cluster" $e.identity.project.ref }}
{{- end }}
  type: confidential
  authMethod: basic
  accessTokenType: jwt
  accessTokenRoleAssertion: false
  idTokenRoleAssertion: false
  idTokenUserinfoAssertion: true
  # One redirect per protected host — the proxy owns {{ $proxyPrefix }}.
  redirectUris:
    - https://{{ $hostname }}{{ $proxyPrefix }}/callback
  postLogoutRedirectUris:
    # oauth2-proxy sends the ROOT (with and without the trailing slash);
    # Zitadel matches exactly, so register both.
    - https://{{ $hostname }}
    - https://{{ $hostname }}/
  secretRef:
    name: {{ include "gateway-auth.oidcSecretName" $root }}
    # Key names match what oauth2-proxy's env reads below.
    keys:
      clientId: client-id
      clientSecret: client-secret
{{- end }}
{{- /* Per-install session store. exposure.sessionStore.url points every
   proxy at ONE Valkey instead, which is the other half of a shared
   session: same cookie secret, same store, same cookie domain. */ -}}
{{- if not (($e.sessionStore | default dict).url) }}
---
# Session / ticket store — one ValkeyCluster PER install (the design's
# per-install Valkey). The valkey.io operator (valkey.io/v1alpha1) owns
# everything downstream: the ValkeyNode pods, the users ACL Secret, and the
# headless Service {{ include "gateway-auth.valkeyHost" $root }} (ClusterIP:
# None, 6379/TCP). This chart creates NO Service or Secret for it.
apiVersion: valkey.io/v1alpha1
kind: ValkeyCluster
metadata:
  name: {{ include "gateway-auth.valkeyName" $root }}
  annotations:
    {{- include "gateway-auth.resourceAnnotations" (dict "root" $root "wave" "5") | nindent 4 }}
  labels:
    {{- include "gateway-auth.labels" $root | nindent 4 }}
spec:
  # One shard, no replica by default. The operator still forms a Valkey
  # Cluster (CLUSTER MEET / slot assignment), so oauth2-proxy must be
  # cluster-aware here exactly as at shards>1 (redis_use_cluster = true).
  shards: {{ int $e.valkey.shards }}
  replicas: {{ int $e.valkey.replicas }}
  {{- with $e.valkey.image }}
  image: {{ . | quote }}
  {{- end }}
  {{- if $e.valkey.persistence.enabled }}
  persistence:
    size: {{ required "exposure.valkey.persistence.size is required when persistence is enabled" $e.valkey.persistence.size }}
    {{- with $e.valkey.persistence.storageClassName }}
    storageClassName: {{ . | quote }}
    {{- end }}
    {{- with $e.valkey.persistence.reclaimPolicy }}
    reclaimPolicy: {{ . }}
    {{- end }}
  {{- end }}
  {{- with $e.valkey.resources }}
  resources:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with $e.valkey.config }}
  config:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with $e.valkey.users }}
  users:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  exporter:
    enabled: {{ $e.valkey.exporter.enabled }}
{{- /* The generated cookie secret is per-install. When several proxies
   must share one session, exposure.cookie.existingSecret points them at
   a common Secret instead and this generator is skipped. */ -}}
{{- if not (($e.cookie | default dict).existingSecret) }}
{{- end }}
---
# Cookie secret — AES-256 for oauth2-proxy's session ticket, generated
# IN-CLUSTER by the ESO Password generator. The value never exists in SSM
# or git. length 32 + no symbols = a 32-byte key oauth2-proxy accepts
# directly. CreatedOnce: stable after first reconcile; rotation = delete the
# Secret (logs everyone out).
apiVersion: generators.external-secrets.io/v1alpha1
kind: Password
metadata:
  name: {{ include "gateway-auth.cookieName" $root }}
  annotations:
    {{- include "gateway-auth.resourceAnnotations" (dict "root" $root "wave" "5") | nindent 4 }}
  labels:
    {{- include "gateway-auth.labels" $root | nindent 4 }}
spec:
  length: 32
  symbols: 0
  symbolCharacters: ""
  noUpper: false
  allowRepeat: true
{{- end }}
{{- if not (($e.cookie | default dict).existingSecret) }}
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: {{ include "gateway-auth.cookieName" $root }}
  annotations:
    {{- include "gateway-auth.resourceAnnotations" (dict "root" $root "wave" "5") | nindent 4 }}
  labels:
    {{- include "gateway-auth.labels" $root | nindent 4 }}
spec:
  refreshPolicy: CreatedOnce
  target:
    name: {{ include "gateway-auth.cookieName" $root }}
    creationPolicy: Owner
  dataFrom:
    - sourceRef:
        generatorRef:
          apiVersion: generators.external-secrets.io/v1alpha1
          kind: Password
          name: {{ include "gateway-auth.cookieName" $root }}
      rewrite:
        - regexp:
            source: "^password$"
            target: "OAUTH2_PROXY_COOKIE_SECRET"
{{- end }}
---
apiVersion: v1
kind: Service
metadata:
  name: {{ include "gateway-auth.proxyName" $root }}
  labels:
    {{- include "gateway-auth.labels" $root | nindent 4 }}
    {{- include "gateway-auth.proxySelectorLabels" $root | nindent 4 }}
  annotations:
    {{- include "gateway-auth.resourceAnnotations" (dict "root" $root "wave" "15") | nindent 4 }}
spec:
  selector:
    {{- include "gateway-auth.proxySelectorLabels" $root | nindent 4 }}
  ports:
    - name: http
      port: 4180
      targetPort: 4180
      protocol: TCP
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "gateway-auth.proxyName" $root }}
  labels:
    {{- include "gateway-auth.labels" $root | nindent 4 }}
    {{- include "gateway-auth.proxySelectorLabels" $root | nindent 4 }}
  annotations:
    {{- include "gateway-auth.resourceAnnotations" (dict "root" $root "wave" "15") | nindent 4 }}
spec:
  # Stateless: sessions live in Valkey, so >1 replica is safe and gives the
  # ext_authz path node-churn resilience.
  replicas: {{ $e.proxy.replicas | default 2 }}
  selector:
    matchLabels:
      {{- include "gateway-auth.proxySelectorLabels" $root | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "gateway-auth.proxySelectorLabels" $root | nindent 8 }}
      annotations:
        # Roll the pods when the config changes — oauth2-proxy reads its
        # config only at startup, so a ConfigMap edit alone does nothing.
        checksum/config: {{ include "gateway-auth.oauth2ProxyCfg" $root | sha256sum }}
        {{- with $root.Values.podAnnotations }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
    spec:
      {{- with $e.proxy.nodeSelector }}
      nodeSelector:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with $e.proxy.tolerations }}
      tolerations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with $e.proxy.topologySpreadConstraints }}
      topologySpreadConstraints:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      containers:
        - name: oauth2-proxy
          image: {{ printf "%s:%s" (required "exposure.proxy.image.repository is required" $e.proxy.image.repository) (required "exposure.proxy.image.tag is required" $e.proxy.image.tag) }}
          args:
            - --config=/etc/oauth2-proxy/oauth2-proxy.cfg
          env:
            # Client id/secret from the operator-minted Secret.
            - name: OAUTH2_PROXY_CLIENT_ID
              valueFrom:
                secretKeyRef:
                  name: {{ include "gateway-auth.oidcSecretName" $root }}
                  key: client-id
            - name: OAUTH2_PROXY_CLIENT_SECRET
              valueFrom:
                secretKeyRef:
                  name: {{ include "gateway-auth.oidcSecretName" $root }}
                  key: client-secret
            # Cookie secret from the ESO Password generator.
            - name: OAUTH2_PROXY_COOKIE_SECRET
              valueFrom:
                secretKeyRef:
                  name: {{ include "gateway-auth.cookieName" $root }}
                  key: OAUTH2_PROXY_COOKIE_SECRET
          ports:
            - name: http
              containerPort: 4180
          readinessProbe:
            httpGet:
              path: /ready
              port: 4180
            initialDelaySeconds: 5
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /ping
              port: 4180
            initialDelaySeconds: 10
            periodSeconds: 20
          resources:
            {{- toYaml ($e.proxy.resources | default (dict "requests" (dict "cpu" "25m" "memory" "64Mi") "limits" (dict "memory" "128Mi"))) | nindent 12 }}
          volumeMounts:
            - name: config
              mountPath: /etc/oauth2-proxy
              readOnly: true
      volumes:
        - name: config
          configMap:
            name: {{ include "gateway-auth.proxyName" $root }}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ include "gateway-auth.proxyName" $root }}
  labels:
    {{- include "gateway-auth.labels" $root | nindent 4 }}
  annotations:
    {{- include "gateway-auth.resourceAnnotations" (dict "root" $root "wave" "15") | nindent 4 }}
data:
  # oauth2-proxy in ext_authz mode: reverse_proxy + upstream static://200
  # returns 200 for an authenticated request or a 302 to sign_in otherwise.
  # set_xauthrequest + pass_access_token put the ACCESS token in the
  # X-Auth-Request-Access-Token header, which the SecurityPolicy copies to
  # the backend and the jwt provider reads via extractFrom. The body lives
  # in the gateway-auth.oauth2ProxyCfg template so the pod's checksum/config
  # annotation can hash the same content.
  oauth2-proxy.cfg: |
{{ include "gateway-auth.oauth2ProxyCfg" $root | indent 4 }}
---
# oauth2-proxy's own endpoints (sign_in, start, callback, sign-out) on the
# exposure host — routed to THIS install's proxy and carrying NO
# SecurityPolicy, so the code flow is reachable unauthenticated. Prefix
# {{ $proxyPrefix }}/ is more specific than a "/" app route, so it wins for
# these paths (INF-562).
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: {{ $name }}-proxy
  annotations:
    {{- include "gateway-auth.resourceAnnotations" (dict "root" $root "wave" "20") | nindent 4 }}
  labels:
    {{- include "gateway-auth.labels" $root | nindent 4 }}
spec:
  parentRefs:
    - group: gateway.networking.k8s.io
      kind: Gateway
      name: {{ required "exposure.gateway.name is required" $gw.name }}
      namespace: {{ required "exposure.gateway.namespace is required" $gw.namespace }}
      sectionName: {{ required "exposure.gateway.sectionName is required" $gw.sectionName }}
  hostnames:
    - "{{ $hostname }}"
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: {{ $proxyPrefix }}/
      backendRefs:
        # Spell out the API-server defaults (group ""/kind Service/weight 1)
        # — an undeclared default is a permanent ArgoCD OutOfSync.
        - group: ""
          kind: Service
          name: {{ include "gateway-auth.proxyName" $root }}
          port: 4180
          weight: 1
{{- range $route := $routes }}
{{- $rname := required "each exposure.routes entry needs a name" $route.name }}
{{- /* Attach mode: when targetRouteName is set, the SecurityPolicy is bound to
   an EXISTING HTTPRoute (owned elsewhere — e.g. a ring3 app chart), and this
   chart creates NO app route or backend. Without it, the chart owns the app
   route (the platform-tier shape). The proxy {proxyPrefix} route is always
   chart-owned regardless. */}}
{{- $targetRoute := $route.targetRouteName | default "" }}
{{- $attach := ne $targetRoute "" }}
{{- $secTarget := ternary $targetRoute (printf "%s-%s" $name $rname) $attach }}
{{- if not $attach }}
{{- $rpath := $route.path | default "/" }}
{{- $rpathType := $route.pathType | default "PathPrefix" }}
{{- $backend := $route.backend | default $e.backend }}
{{- if not $backend }}
{{- fail (printf "route %q has no backend and exposure.backend is unset (set exposure.routes[].targetRouteName to attach the SecurityPolicy to an existing route instead of creating one)" $rname) }}
{{- end }}
---
# Application route {{ $rname }} ({{ $rpath }}) → backend Service
# {{ $backend.name }}:{{ $backend.port }}.
{{- if $route.protected }}
# Protected: the SecurityPolicy below enforces the OIDC ext_authz + jwt
# flow on this route.
{{- else }}
# Anonymous by construction: NO SecurityPolicy (the eudi wallet/issuer/Hydra
# case — a phone wallet has no employee session; its security is
# protocol-level).
{{- end }}
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: {{ $name }}-{{ $rname }}
  annotations:
    {{- include "gateway-auth.resourceAnnotations" (dict "root" $root "wave" "20") | nindent 4 }}
  labels:
    {{- include "gateway-auth.labels" $root | nindent 4 }}
spec:
  parentRefs:
    - group: gateway.networking.k8s.io
      kind: Gateway
      name: {{ $gw.name }}
      namespace: {{ $gw.namespace }}
      sectionName: {{ $gw.sectionName }}
  hostnames:
    - "{{ $hostname }}"
  rules:
    - matches:
        - path:
            type: {{ $rpathType }}
            value: {{ $rpath }}
      backendRefs:
        - group: ""
          kind: Service
          name: {{ required "route backend needs a name" $backend.name }}
          port: {{ required "route backend needs a port" $backend.port }}
          weight: 1
{{- end }}
{{- if $route.protected }}
---
# extAuth + jwt authorization on route {{ $rname }}
{{- if $attach }} (attached to the existing HTTPRoute {{ $secTarget }}){{ end }}.
# oauth2-proxy runs the OIDC code flow and holds the tokens in Valkey; Envoy
# calls it as HTTP ext_authz. It returns 200 with X-Auth-Request-Access-Token,
# which the jwt provider below re-validates against Zitadel's JWKS. The shared
# EnvoyProxy filterOrder puts ext_authz before jwt_authn so the header exists
# by the time jwt_authn runs (INF-562 / INF-421).
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: SecurityPolicy
metadata:
  name: {{ $name }}-{{ $rname }}
  annotations:
    {{- include "gateway-auth.resourceAnnotations" (dict "root" $root "wave" "20") | nindent 4 }}
  labels:
    {{- include "gateway-auth.labels" $root | nindent 4 }}
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: {{ $secTarget }}
  extAuth:
    # HTTP ext_authz forwards ONLY these client headers to the auth service
    # (unlike gRPC, which forwards all). Without `cookie`, oauth2-proxy never
    # sees the session it set at the callback → infinite login loop. The
    # x-forwarded-* headers let oauth2-proxy (reverse_proxy) reconstruct the
    # original URL for its redirects (INF-562).
    headersToExtAuth:
      - cookie
      - x-forwarded-proto
      - x-forwarded-host
      - x-forwarded-uri
    http:
      backendRefs:
        # Spell out the API-server defaults — an undeclared default is a
        # permanent ArgoCD OutOfSync.
        - group: ""
          kind: Service
          name: {{ include "gateway-auth.proxyName" $root }}
          port: 4180
          weight: 1
      # Response headers oauth2-proxy sets that Envoy copies onto the request
      # before jwt_authn runs (the access token is the one the jwt provider
      # reads via extractFrom).
      headersToBackend:
        - x-auth-request-access-token
        - x-auth-request-user
        - x-auth-request-email
        - x-auth-request-groups
{{- if $e.passAuthorizationHeader }}
        # passAuthorizationHeader's other half: the proxy SETS the standard
        # Authorization header (set_authorization_header above), but in
        # ext_authz mode Envoy copies only the LISTED auth-response headers
        # onto the backend request — without this line the header is dropped
        # at the gateway and the knob is dead for every consumer
        # (url-shortener /api/me answered anonymous behind a proxy that was
        # demonstrably setting the header; 2026-08-27).
        - authorization
{{- end }}
{{- if $route.authenticatedOnly }}
  # authenticatedOnly: ext_authz (oauth2-proxy) is the whole gate — any org
  # user who completed the OIDC login passes, and the token is still forwarded
  # to the backend (headersToBackend above) for the app to authorize itself.
  # No jwt/groups block: this is the business-app posture (the app gates its
  # own actions), the same as the Envoy `oidc`-only exposure it replaces.
{{- else }}
  # Authorization (INF-421): "authenticated" is never sufficient — any org
  # user passes ext_authz above. The jwt provider re-validates the access
  # token against Zitadel's JWKS, and the rules require a group in the
  # allow-list. defaultAction Deny: a fresh user with zero grants gets 403,
  # not the app.
  jwt:
    providers:
      - name: {{ default "zitadel" $e.identity.mode }}
        issuer: "{{ $issuer }}"
        remoteJWKS:
          {{- /* Zitadel serves its keys at /oauth/v2/keys; nothing else does.
             exposure.identity.jwksUri overrides the whole URI so the chart can
             front any provider (dex uses /keys, Keycloak a realm path). */}}
          uri: "{{ $e.identity.jwksUri | default (printf "%s/oauth/v2/keys" $issuer) }}"
          # Explicit (matches the CRD default): the API server injects it,
          # and an undeclared default is a permanent ArgoCD OutOfSync.
          cacheDuration: "300s"
        # The token arrives from oauth2-proxy, not the Authorization header.
        extractFrom:
          headers:
            - name: X-Auth-Request-Access-Token
  authorization:
    defaultAction: Deny
    rules:
      - name: groups-allow
        action: Allow
        principal:
          jwt:
            provider: zitadel
            claims:
              - name: groups
                valueType: StringArray
                values:
                  {{- range (required "exposure.authorization.groups must be set for a protected route" $e.authorization.groups) }}
                  - {{ . | quote }}
                  {{- end }}
{{- end }}
{{- end }}
{{- end }}
{{- if $e.networkPolicy.enabled }}
---
# Ingress-from-fleet NetworkPolicy: admit the shared Envoy data-plane to
# THIS install's oauth2-proxy on the ext_authz port. Selector copied from
# the eudi-infra envoy rule: the namespaceSelector and podSelector sit in
# the SAME `from` element so they AND together, and
# app.kubernetes.io/name: envoy matches the data-plane proxy pods only (the
# control plane carries app.kubernetes.io/name: gateway-helm).
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ include "gateway-auth.proxyName" $root }}-ingress
  annotations:
    {{- include "gateway-auth.resourceAnnotations" (dict "root" $root "wave" "0") | nindent 4 }}
  labels:
    {{- include "gateway-auth.labels" $root | nindent 4 }}
spec:
  podSelector:
    matchLabels:
      {{- include "gateway-auth.proxySelectorLabels" $root | nindent 6 }}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: {{ $e.networkPolicy.fleetNamespace | default "envoy-gateway-system" }}
          podSelector:
            matchLabels:
              app.kubernetes.io/name: envoy
      ports:
        - port: {{ int ($e.networkPolicy.port | default 4180) }}
          protocol: TCP
---
# Valkey session-store ingress NetworkPolicy. Two admitted clients, because
# defining ANY Ingress rule flips these pods to default-deny for every other
# source:
#   1. the valkey-operator, so it can form the shard (CLUSTER MEET / slot
#      assignment on 6379 + the 16379 cluster bus) and mark the cluster Ready;
#   2. THIS install's own oauth2-proxy, which holds its OIDC sessions here
#      (redis://…:6379) — without it the proxy's dial times out, it crashloops
#      on "unable to set a redis initialization key", and ext_authz has no
#      healthy upstream (Envoy returns "remote connection failure" / 403).
# A business-app namespace runs a default-deny tenant baseline that admits only
# cnpg/envoy/tailscale cross-namespace; platform namespaces
# (kube-system/gemaal-system/identity-system) lack that baseline, so before
# rule 1 existed the operator gap was invisible there — and rule 2 was missing
# entirely until a proxy restart made the block bite.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ include "gateway-auth.valkeyName" $root }}-operator
  annotations:
    {{- include "gateway-auth.resourceAnnotations" (dict "root" $root "wave" "0") | nindent 4 }}
  labels:
    {{- include "gateway-auth.labels" $root | nindent 4 }}
spec:
  podSelector:
    matchLabels:
      valkey.io/cluster: {{ include "gateway-auth.valkeyName" $root }}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: {{ $e.networkPolicy.valkeyOperatorNamespace | default "valkey-operator-system" }}
      ports:
        - port: 6379
          protocol: TCP
        - port: 16379
          protocol: TCP
    - from:
        - podSelector:
            matchLabels:
              {{- include "gateway-auth.proxySelectorLabels" $root | nindent 14 }}
      ports:
        - port: 6379
          protocol: TCP
{{- end }}
{{- end -}}
{{- end -}}
