/**
 * Identity is who the caller is, as far as a service is concerned.
 *
 * `roles` are the raw claim values (the gateway's groups claim, e.g.
 * "cluster-kernel:roster:operator"); each service maps these to its own
 * permission model. `token` is the verified access token, kept so a handler can
 * call a downstream API (or userinfo) as the caller. `claims` is every claim,
 * for the app-specific reads the typed fields do not cover.
 */
export interface Identity {
    subject: string;
    name: string;
    email: string;
    roles: string[];
    token: string;
    claims: Record<string, unknown>;
}
/** hasRole reports whether the caller holds the exact role value. */
export declare function hasRole(identity: Identity, role: string): boolean;
/** hasAnyRole reports whether the caller holds at least one of the roles. */
export declare function hasAnyRole(identity: Identity, ...roles: string[]): boolean;
/**
 * Headers is the minimal view of a request an Authenticator needs — one method,
 * so every framework adapter (node http, express, hono, fetch) wraps its own
 * request type in a few lines and the core stays framework-agnostic. A
 * cookie-borne token is read by a TokenSource that parses the "cookie" header,
 * so no cookie accessor is needed here.
 */
export interface Headers {
    /**
     * get returns a header value, or undefined if absent. Names are canonicalized
     * case-insensitively by the adapter.
     */
    get(name: string): string | undefined;
}
/**
 * NoCredentialError means no token/identity was presented — the request almost
 * certainly did not come through the gateway. Adapters map it to 401.
 */
export declare class NoCredentialError extends Error {
    constructor(message?: string);
}
/**
 * InvalidTokenError means a credential was presented but failed verification.
 * Adapters map it to 401; the detailed reason is carried on `cause` for logging,
 * never returned to the caller.
 */
export declare class InvalidTokenError extends Error {
    constructor(message?: string, options?: {
        cause?: unknown;
    });
}
/**
 * Authenticator resolves a request into an Identity.
 *
 * Implementations: the JWKS verifier (createVerifier / the profile presets), the
 * header-trust authenticator (headerTrust), and the dev-only disabled one
 * (disabled). All satisfy this interface, so an adapter is written once.
 */
export interface Authenticator {
    /**
     * authenticate extracts the caller's credential from the request, verifies it
     * (unless in trust mode), and resolves to the mapped Identity. It rejects with
     * NoCredentialError or InvalidTokenError on failure.
     */
    authenticate(headers: Headers): Promise<Identity>;
    /**
     * enabled reports whether credentials are actually being verified. A service
     * can relax role checks in local development when this is false.
     */
    enabled(): boolean;
}
/**
 * Logger is the minimal sink the verifier and userinfo fallback write to. A
 * failed verification's reason goes here, not to the caller. Defaults to
 * console; pass a noop to silence.
 */
export interface Logger {
    warn(message: string, meta?: Record<string, unknown>): void;
}
/** consoleLogger is the default Logger. */
export declare const consoleLogger: Logger;
/** noopLogger discards everything — convenient for tests. */
export declare const noopLogger: Logger;
/**
 * disabled returns an authenticator that authorizes everybody as the given
 * roles, for local development and tests. Pass the service's operator-level
 * role(s) so dev matches production's most-privileged path. Reachable only
 * through an explicit opt-in, never as a fallback from a misconfiguration.
 */
export declare function disabled(...roles: string[]): Authenticator;
//# sourceMappingURL=identity.d.ts.map