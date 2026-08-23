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
        --set exposure.routes[0].targetRouteName=url-shortener \
        --set exposure.proxy.image.repository=quay.io/oauth2-proxy/oauth2-proxy \
        --set exposure.proxy.image.tag=v7.6.0 \
        --set 'exposure.authorization.groups={cluster-x:cluster:admin}' >/dev/null

# Type-check, test and build the TS package.
ts:
    cd ts && npm ci && npx tsc --noEmit && npx vitest run && npx tsc -p tsconfig.build.json

# Everything CI runs.
check: build test lint chart-lint ts
