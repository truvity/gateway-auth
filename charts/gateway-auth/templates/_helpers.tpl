{{/*
resourceAnnotations merges the ArgoCD sync-wave (intra-chart ordering when
the chart is ArgoCD-managed — plain helm ignores it) with user-supplied
commonAnnotations. Usage:
  include "gateway-auth.resourceAnnotations" (dict "root" $ "wave" "10")
Mirrors url-shortener-infra / eudi-infra so consumer charts get the same
sync-wave discipline.
*/}}
{{- define "gateway-auth.resourceAnnotations" -}}
argocd.argoproj.io/sync-wave: {{ .wave | quote }}
{{- with .root.Values.commonAnnotations }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/*
name is the base every resource this exposure owns derives from — the
OIDCApp, the ValkeyCluster, the cookie Secret, the oauth2-proxy
Deployment/Service/ConfigMap, the HTTPRoutes and SecurityPolicies. One
oauth2-proxy per OIDC client means this must be unique per install in the
target namespace. Defaults to the release name; override with
exposure.name. Validated as a DNS-1123 label so every derived K8s name is
legal.
*/}}
{{- define "gateway-auth.name" -}}
{{- $name := (.Values.exposure.name | default .Release.Name) -}}
{{- if not (regexMatch "^[a-z0-9]([a-z0-9-]{0,45}[a-z0-9])?$" $name) -}}
{{- fail (printf "exposure.name %q must be a lowercase DNS-1123 label of at most 47 chars (it feeds the OIDCApp, ValkeyCluster, cookie Secret, oauth2-proxy workload and every HTTPRoute/SecurityPolicy)" $name) -}}
{{- end -}}
{{- $name -}}
{{- end -}}

{{/*
proxyName is the oauth2-proxy Deployment/Service/ConfigMap name for this
install: {name}-oauth2-proxy. Per-install (not the shared "oauth2-proxy" of
the gitops gateways stack) because this chart runs one proxy per OIDC
client.
*/}}
{{- define "gateway-auth.proxyName" -}}
{{- printf "%s-oauth2-proxy" (include "gateway-auth.name" .) -}}
{{- end -}}

{{/*
valkeyName is the per-install ValkeyCluster CR name: {name}-sessions.
*/}}
{{- define "gateway-auth.valkeyName" -}}
{{- printf "%s-sessions" (include "gateway-auth.name" .) -}}
{{- end -}}

{{/*
valkeyHost is the in-cluster DNS name oauth2-proxy dials. The
valkey.io operator names its headless Service "valkey-" + <ValkeyCluster
name> (ClusterIP: None, 6379/TCP) — operator-owned, so this chart creates
NO Service of its own for the Valkey pods (the gateways-stack and
eudi-infra precedents).
*/}}
{{- define "gateway-auth.valkeyHost" -}}
{{- printf "valkey-%s" (include "gateway-auth.valkeyName" .) -}}
{{- end -}}

{{/*
oidcSecretName is the operator-minted client-id/secret Secret.
*/}}
{{- define "gateway-auth.oidcSecretName" -}}
{{- printf "%s-oidc-client" (include "gateway-auth.name" .) -}}
{{- end -}}

{{/*
cookieName is the ESO Password + ExternalSecret cookie secret name.
*/}}
{{- define "gateway-auth.cookieName" -}}
{{- printf "%s-cookie" (include "gateway-auth.name" .) -}}
{{- end -}}

{{/*
dnsDomain is the cluster DNS suffix used to build the Valkey service FQDN.
Mirrors the gateways-stack reference's
(.Values.network | default dict).dnsDomain | default "cluster.local".
*/}}
{{- define "gateway-auth.dnsDomain" -}}
{{- .Values.exposure.dnsDomain | default "cluster.local" -}}
{{- end -}}

{{/*
Common labels for every object this exposure owns.
*/}}
{{- define "gateway-auth.labels" -}}
app.kubernetes.io/name: gateway-auth
app.kubernetes.io/instance: {{ include "gateway-auth.name" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
tenancy.truvity.io/layer: infra
tenancy.truvity.io/component: gateway-auth
{{- end -}}

{{/*
proxySelectorLabels are the pod selector for the oauth2-proxy
Deployment/Service AND the NetworkPolicy. DEVIATION from the gateways-stack
reference (which selects on app.kubernetes.io/name: oauth2-proxy alone,
correct for a single shared proxy): this chart runs one proxy PER install,
so `instance` is added to keep two installs' proxies in the same namespace
from cross-selecting each other's pods.
*/}}
{{- define "gateway-auth.proxySelectorLabels" -}}
app.kubernetes.io/name: oauth2-proxy
app.kubernetes.io/instance: {{ include "gateway-auth.name" . }}
{{- end -}}
