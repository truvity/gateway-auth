import type { Headers } from "./identity.js";
/**
 * HEADER carries the header names oauth2-proxy sets, plus Authorization.
 * Lookups are case-insensitive, so the canonical casing here is cosmetic.
 */
export declare const HEADER: {
    /**
     * accessToken carries the verified access token oauth2-proxy forwards
     * (set_xauthrequest + pass_access_token). Not "Bearer"-prefixed.
     */
    readonly accessToken: "x-auth-request-access-token";
    /** user / email / groups are oauth2-proxy's pre-parsed identity headers — trust mode only. */
    readonly user: "x-auth-request-user";
    readonly email: "x-auth-request-email";
    readonly groups: "x-auth-request-groups";
    /** authorization is the standard bearer header, for direct API callers and tests. */
    readonly authorization: "authorization";
};
/** TokenSource pulls a raw (still-encoded) token out of a request, or undefined. */
export type TokenSource = (headers: Headers) => string | undefined;
/**
 * headerSource reads a token from one request header.
 *
 * `scheme`, if set, is stripped case-insensitively together with a following
 * space: scheme "Bearer" turns "Bearer abc" into "abc" (RFC 7235 makes the
 * scheme case-insensitive, and proxies do vary it). Omitting `scheme` reads the
 * header verbatim — how oauth2-proxy sets x-auth-request-access-token.
 */
export declare function headerSource(name: string, scheme?: string): TokenSource;
/** chain tries each source in order and returns the first token found. */
export declare function chain(...sources: TokenSource[]): TokenSource;
/** oauth2ProxyAccessToken reads the access token oauth2-proxy injects. */
export declare function oauth2ProxyAccessToken(): TokenSource;
/** authorizationBearer reads a bearer token from the Authorization header. */
export declare function authorizationBearer(): TokenSource;
/**
 * defaultSource tries the oauth2-proxy header first, then Authorization —
 * covering both a gateway-fronted request and a direct API caller.
 */
export declare function defaultSource(): TokenSource;
/**
 * splitAndTrim splits on sep and drops empty/whitespace entries — for the
 * comma-separated groups header.
 */
export declare function splitAndTrim(value: string, sep: string): string[];
//# sourceMappingURL=source.d.ts.map