// Core contract: Identity, Headers, the sentinel error types, and the
// Authenticator interface every mode implements.
//
// This mirrors the Go gatewayauth package: the login (the authorization code
// flow, the session, the redirect dance) belongs to the gateway in front of the
// service. What is left for the service is knowing WHO the caller is and WHICH
// of the service's own roles they hold, because that changes which handlers
// refuse. The forwarded token is verified again here rather than trusted (the
// default mode); a trust mode is offered where the NetworkPolicy genuinely is
// the boundary, opt-in, never a fallback.
/** hasRole reports whether the caller holds the exact role value. */
export function hasRole(identity, role) {
    return identity.roles.includes(role);
}
/** hasAnyRole reports whether the caller holds at least one of the roles. */
export function hasAnyRole(identity, ...roles) {
    return roles.some((role) => hasRole(identity, role));
}
/**
 * NoCredentialError means no token/identity was presented — the request almost
 * certainly did not come through the gateway. Adapters map it to 401.
 */
export class NoCredentialError extends Error {
    constructor(message = "gatewayauth: no credential presented") {
        super(message);
        this.name = "NoCredentialError";
    }
}
/**
 * InvalidTokenError means a credential was presented but failed verification.
 * Adapters map it to 401; the detailed reason is carried on `cause` for logging,
 * never returned to the caller.
 */
export class InvalidTokenError extends Error {
    constructor(message = "gatewayauth: credential verification failed", options) {
        super(message, options);
        this.name = "InvalidTokenError";
    }
}
/** consoleLogger is the default Logger. */
export const consoleLogger = {
    warn(message, meta) {
        if (meta) {
            console.warn(`gatewayauth: ${message}`, meta);
        }
        else {
            console.warn(`gatewayauth: ${message}`);
        }
    },
};
/** noopLogger discards everything — convenient for tests. */
export const noopLogger = { warn() { } };
// ---------------------------------------------------------------------------
// disabled — local development only.
// ---------------------------------------------------------------------------
/**
 * disabled returns an authenticator that authorizes everybody as the given
 * roles, for local development and tests. Pass the service's operator-level
 * role(s) so dev matches production's most-privileged path. Reachable only
 * through an explicit opt-in, never as a fallback from a misconfiguration.
 */
export function disabled(...roles) {
    const identity = {
        subject: "local",
        name: "local operator",
        email: "local@localhost",
        roles,
        token: "",
        claims: {},
    };
    return {
        enabled: () => false,
        authenticate: () => Promise.resolve(identity),
    };
}
//# sourceMappingURL=identity.js.map