import type { JWK, JWTVerifyGetKey, KeyLike } from "jose";
import { type Authenticator, type Logger } from "./identity.js";
import { type ClaimsMapper } from "./claims.js";
import { type TokenSource } from "./source.js";
import { type Endpoints, type FetchLike } from "./discovery.js";
/**
 * KeyResolver is anything jose's jwtVerify accepts as its key argument: a remote
 * JWKS getter (the default), a local JWKS getter, or a bare public key. The last
 * two are the testability seam — a test injects a key without any HTTP.
 */
export type KeyResolver = KeyLike | Uint8Array | JWK | JWTVerifyGetKey;
/** CreateVerifierOptions configures a verifying Authenticator. */
export interface CreateVerifierOptions {
    /** issuer is the OIDC issuer URL; discovery derives JWKS + userinfo from it. */
    issuer: string;
    /**
     * audience, if set, is required in the token. Empty accepts any token the
     * issuer minted — the right default behind a gateway that already checked
     * audience, and it avoids naming the wrong value on providers whose access
     * tokens carry a project rather than a client.
     */
    audience?: string;
    /** source pulls the token from the request. Omitted uses defaultSource(). */
    source?: TokenSource;
    /**
     * claims names the claims mapped into an Identity. Omitted uses the
     * OIDC-standard names with "groups" for roles.
     */
    claims?: Partial<ClaimsMapper>;
    /**
     * userinfoFallback fills name/email from the userinfo endpoint when the access
     * token carries neither. Off by default.
     */
    userinfoFallback?: boolean;
    /** logger; omitted uses a console logger. */
    logger?: Logger;
    /**
     * jwks, if given, is used to verify signatures instead of a remote JWKS built
     * from discovery. Pass a jose key resolver (createLocalJWKSet) or a public key
     * to verify without any network I/O. Setting this skips discovery unless
     * `endpoints` is also given.
     */
    jwks?: KeyResolver;
    /**
     * endpoints, if given, is used instead of running OIDC discovery — the
     * jwks_uri and userinfo_endpoint a test would otherwise have to serve.
     */
    endpoints?: Partial<Endpoints>;
    /** fetch used for discovery and userinfo; injectable for tests. */
    fetch?: FetchLike;
}
/**
 * createVerifier builds an Authenticator against the issuer's JWKS. Discovery
 * happens here (unless `endpoints`/`jwks` are injected), so an unreachable or
 * misconfigured issuer fails at startup rather than on the first request. The
 * remote JWKS itself is fetched lazily by jose on the first verification and
 * cached/rotated thereafter.
 */
export declare function createVerifier(opts: CreateVerifierOptions): Promise<Authenticator>;
/**
 * headerTrust returns an Authenticator that builds an Identity from
 * oauth2-proxy's pre-parsed identity headers WITHOUT verifying a token. For
 * surfaces where the ingress-from-fleet NetworkPolicy is genuinely the trust
 * boundary. It still requires the headers to be present, so a request that
 * bypassed the proxy is rejected. The verifying mode is the recommended default.
 */
export declare function headerTrust(): Authenticator;
//# sourceMappingURL=verify.d.ts.map