# Development commands for gateway-auth (Go module + Helm chart + TS package).

# Disable go.work (a parent workspace interferes with standalone module builds).
export GOWORK := "off"
# jwx v4 pulls in encoding/json/v2, gated behind this experiment in go1.26.
# devbox.json sets it for the shell; set it here too so a bare `just` works.
export GOEXPERIMENT := "jsonv2"

# Format all Go files (gofmt + goimports via golangci-lint).
fmt:
    golangci-lint fmt ./...

# Build the Go module.
build: fmt
    go build ./...

# Run Go unit tests.
test:
    go test ./... -coverprofile=coverage.out

# Run Go linters.
lint:
    golangci-lint run ./...

# Render the chart every way its templates can be reached — the exposure path
# is only reachable with exposure.enabled, so a default render never touches
# it. Covers a platform UI (shared cluster project) and a business app
# (product projectRef, custom proxyPrefix, mixed protected/anonymous routes).
chart-lint:
    helm lint charts/gateway-auth
    helm template gateway-auth charts/gateway-auth >/dev/null
    helm template gateway-auth charts/gateway-auth \
        --set exposure.enabled=true \
        --set exposure.hostname=hubble.example.com \
        --set exposure.issuer=https://sso.example.com \
        --set exposure.gateway.name=hubble \
        --set exposure.gateway.namespace=kube-system \
        --set exposure.gateway.sectionName=hubble \
        --set exposure.identity.project.cluster=true \
        --set exposure.identity.projectId=00000000 \
        --set exposure.backend.name=hubble-ui \
        --set exposure.backend.port=80 \
        --set exposure.proxy.image.repository=quay.io/oauth2-proxy/oauth2-proxy \
        --set exposure.proxy.image.tag=v7.6.0 \
        --set 'exposure.authorization.groups={cluster-x:cluster:admin}' \
        --set exposure.networkPolicy.enabled=true >/dev/null
    # The jwt provider BLOCK and the authorization RULE that references it must
    # name the same provider. They diverged once -- the block was named from
    # identity.mode while the rule hardcoded "zitadel" -- so every static-mode
    # install with a groups allow-list answered "RBAC: access denied" for every
    # user. Rendering alone cannot catch it: the output is well-formed either
    # way, so this asserts the two names are equal in both modes.
    bash -eu -c 'for m in static zitadel; do o=$(helm template gateway-auth charts/gateway-auth --set exposure.enabled=true --set exposure.hostname=app.example.com --set exposure.issuer=https://sso.example.com --set exposure.gateway.name=app --set exposure.gateway.namespace=gw --set exposure.gateway.sectionName=https --set exposure.identity.mode=$m --set exposure.identity.existingSecret=idp --set exposure.identity.projectId=00000000 --set exposure.backend.name=app --set exposure.backend.port=80 --set exposure.routes[0].name=app --set exposure.routes[0].protected=true --set "exposure.authorization.groups={org:admins}"); b=$(printf "%s" "$o" | grep -A1 "providers:" | grep -- "- name:" | awk "{print \$3}"); r=$(printf "%s" "$o" | grep "provider:" | awk "{print \$2}"); if [ "$b" != "$r" ]; then echo "jwt provider mismatch mode=$m: block=$b rule=$r" >&2; exit 1; fi; echo "jwt provider names agree in mode=$m ($b)"; done'

    # Attach mode (business app): SecurityPolicy binds to an EXISTING ring3
    # HTTPRoute (targetRouteName), product projectRef, no chart-owned app route.
    helm template gateway-auth charts/gateway-auth \
        --set exposure.enabled=true \
        --set exposure.hostname=us.example.com \
        --set exposure.issuer=https://sso.example.com \
        --set exposure.gateway.name=tenants \
        --set exposure.gateway.namespace=envoy-gateway-system \
        --set exposure.gateway.sectionName=tenants \
        --set exposure.identity.project.cluster=false \
        --set exposure.identity.project.ref=url-shortener \
        --set exposure.passAuthorizationHeader=true \
        --set exposure.routes[0].name=app \
        --set exposure.routes[0].protected=true \
        --set exposure.routes[0].authenticatedOnly=true \
        --set exposure.routes[0].targetRouteName=url-shortener \
        --set exposure.proxy.image.repository=quay.io/oauth2-proxy/oauth2-proxy \
        --set exposure.proxy.image.tag=v7.6.0 >/dev/null

# Type-check, test and build the TS package.
ts:
    cd ts && npm ci && npx tsc --noEmit && npx vitest run && npx tsc -p tsconfig.build.json

# Everything CI runs.
check: build test lint chart-lint ts

# Run Go vulnerability check
vuln:
    govulncheck ./...
