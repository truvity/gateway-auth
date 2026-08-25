// @truvity/gateway-auth — turn a gateway-authenticated request into a verified
// Identity, for the fleet's node web tiers. TypeScript mirror of the Go
// gatewayauth module.
export { hasRole, hasAnyRole, disabled, consoleLogger, noopLogger, NoCredentialError, InvalidTokenError, } from "./identity.js";
export { HEADER, headerSource, chain, oauth2ProxyAccessToken, authorizationBearer, defaultSource, splitAndTrim, } from "./source.js";
export { claimsMapper, identityFromClaims } from "./claims.js";
export { discover } from "./discovery.js";
export { UserinfoFetcher, userinfoTTL } from "./userinfo.js";
export { createVerifier, headerTrust, } from "./verify.js";
export { oauth2ProxyOIDC } from "./profile.js";
export { signOutUrl } from "./signout.js";
export { fromNodeHeaders, fromFetchHeaders, middleware, requireRoles, } from "./adapters.js";
//# sourceMappingURL=index.js.map