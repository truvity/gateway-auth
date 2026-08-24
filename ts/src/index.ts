// @truvity/gateway-auth — turn a gateway-authenticated request into a verified
// Identity, for the fleet's node web tiers. TypeScript mirror of the Go
// gatewayauth module.

export {
  type Identity,
  type Headers,
  type Authenticator,
  type Logger,
  hasRole,
  hasAnyRole,
  disabled,
  consoleLogger,
  noopLogger,
  NoCredentialError,
  InvalidTokenError,
} from "./identity.js";

export {
  type TokenSource,
  HEADER,
  headerSource,
  chain,
  oauth2ProxyAccessToken,
  authorizationBearer,
  defaultSource,
  splitAndTrim,
} from "./source.js";

export { type ClaimsMapper, claimsMapper, identityFromClaims } from "./claims.js";

export { type Endpoints, type FetchLike, discover } from "./discovery.js";

export { UserinfoFetcher, userinfoTTL } from "./userinfo.js";

export {
  type CreateVerifierOptions,
  type KeyResolver,
  createVerifier,
  headerTrust,
} from "./verify.js";

export { type ProfileOptions, oauth2ProxyOIDC } from "./profile.js";

export { signOutUrl } from "./signout.js";

export {
  type RequestLike,
  type ResponseLike,
  type NextFn,
  type Middleware,
  fromNodeHeaders,
  fromFetchHeaders,
  middleware,
  requireRoles,
} from "./adapters.js";
