// Package humamw adapts gatewayauth to Huma v2, as a registered security
// scheme surfaced in the generated OpenAPI plus an enforcing middleware.
//
// An operation opts in declaratively:
//
//	huma.Register(api, huma.Operation{
//		OperationID: "sync",
//		Method:      http.MethodPost,
//		Path:        "/sync",
//		Security:    []map[string][]string{{humamw.SchemeName: {"cluster-kernel:roster:operator"}}},
//	}, handler)
//
// The scopes list the roles the operation requires (any-of). An operation with
// no entry for SchemeName is left anonymous.
package humamw

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	gatewayauth "github.com/truvity/gateway-auth"
)

// SchemeName is the OpenAPI security-scheme key operations reference.
const SchemeName = "gatewayAuth"

// Register adds the security scheme to the API's OpenAPI document and installs
// the enforcing middleware. Call once, after huma.New.
func Register(api huma.API, auth gatewayauth.Authenticator) {
	registerScheme(api)
	api.UseMiddleware(middleware(api, auth))
}

func registerScheme(api huma.API) {
	oapi := api.OpenAPI()
	if oapi.Components == nil {
		oapi.Components = &huma.Components{}
	}

	if oapi.Components.SecuritySchemes == nil {
		oapi.Components.SecuritySchemes = map[string]*huma.SecurityScheme{}
	}

	oapi.Components.SecuritySchemes[SchemeName] = &huma.SecurityScheme{
		Type:         "http",
		Scheme:       "bearer",
		BearerFormat: "JWT",
		Description: "Access token forwarded by the gateway (oauth2-proxy) and re-verified " +
			"against the issuer's JWKS. The scopes of an operation list the roles it requires.",
	}
}

func middleware(api huma.API, auth gatewayauth.Authenticator) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		roles, required := requiredRoles(ctx.Operation())
		if !required {
			next(ctx)

			return
		}

		identity, err := auth.Authenticate(ctx.Context(), humaHeaders{ctx})
		if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized,
				"authentication required: reach this service through the gateway")

			return
		}

		if auth.Enabled() && len(roles) > 0 && !identity.HasAnyRole(roles...) {
			_ = huma.WriteErr(api, ctx, http.StatusForbidden,
				"your account holds none of the required roles")

			return
		}

		next(huma.WithValue(ctx, gatewayauth.ContextKey{}, identity))
	}
}

// requiredRoles returns the roles an operation requires under SchemeName, and
// whether the scheme is declared on it at all.
func requiredRoles(op *huma.Operation) ([]string, bool) {
	if op == nil {
		return nil, false
	}

	for _, requirement := range op.Security {
		if scopes, ok := requirement[SchemeName]; ok {
			return scopes, true
		}
	}

	return nil, false
}

type humaHeaders struct{ ctx huma.Context }

func (h humaHeaders) Get(name string) string { return h.ctx.Header(name) }
