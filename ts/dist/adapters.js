// Framework adapters — wrap a request's headers as the core `Headers` view, and
// an express-style middleware that attaches `req.identity` and maps the sentinel
// errors to 401/403.
import { hasAnyRole, InvalidTokenError, NoCredentialError, } from "./identity.js";
/**
 * fromNodeHeaders wraps node's `req.headers` (IncomingHttpHeaders) as a Headers.
 * Node lowercases header names already; a duplicated header arrives as an array
 * and is joined with ", " so a source still sees one value.
 */
export function fromNodeHeaders(headers) {
    return {
        get(name) {
            const value = headers[name.toLowerCase()];
            if (value === undefined) {
                return undefined;
            }
            return Array.isArray(value) ? value.join(", ") : value;
        },
    };
}
/** fromFetchHeaders wraps a WHATWG Headers (fetch / hono / undici) as a Headers. */
export function fromFetchHeaders(headers) {
    return {
        get(name) {
            return headers.get(name) ?? undefined;
        },
    };
}
/**
 * middleware authenticates the caller, attaches the Identity as `req.identity`,
 * and rejects anyone without a valid credential with 401.
 */
export function middleware(auth) {
    return (req, res, next) => {
        void authenticateThen(auth, req, res, next);
    };
}
/**
 * requireRoles authenticates and additionally requires at least one of the roles
 * (403 otherwise). Role checks are skipped when the authenticator is disabled
 * (local development).
 */
export function requireRoles(auth, ...roles) {
    return (req, res, next) => {
        void authenticateThen(auth, req, res, next, roles);
    };
}
async function authenticateThen(auth, req, res, next, roles) {
    let identity;
    try {
        identity = await auth.authenticate(fromNodeHeaders(req.headers));
    }
    catch (err) {
        sendAuthError(res, err);
        return;
    }
    if (roles && roles.length > 0 && auth.enabled() && !hasAnyRole(identity, ...roles)) {
        res.status(403).json({ error: "your account holds none of the required roles" });
        return;
    }
    req.identity = identity;
    next();
}
/** sendAuthError maps the sentinel errors to 401 without leaking why to the caller. */
function sendAuthError(res, err) {
    if (err instanceof NoCredentialError) {
        res.status(401).json({ error: "authentication required: reach this service through the gateway" });
        return;
    }
    if (err instanceof InvalidTokenError) {
        res.status(401).json({ error: "invalid credential" });
        return;
    }
    res.status(401).json({ error: "authentication failed" });
}
//# sourceMappingURL=adapters.js.map