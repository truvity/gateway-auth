// Framework adapters — wrap a request's headers as the core `Headers` view, and
// an express-style middleware that attaches `req.identity` and maps the sentinel
// errors to 401/403.

import {
  type Authenticator,
  type Headers,
  type Identity,
  hasAnyRole,
  InvalidTokenError,
  NoCredentialError,
} from "./identity.js";

/**
 * fromNodeHeaders wraps node's `req.headers` (IncomingHttpHeaders) as a Headers.
 * Node lowercases header names already; a duplicated header arrives as an array
 * and is joined with ", " so a source still sees one value.
 */
export function fromNodeHeaders(
  headers: Record<string, string | string[] | undefined>,
): Headers {
  return {
    get(name: string): string | undefined {
      const value = headers[name.toLowerCase()];
      if (value === undefined) {
        return undefined;
      }

      return Array.isArray(value) ? value.join(", ") : value;
    },
  };
}

/** fromFetchHeaders wraps a WHATWG Headers (fetch / hono / undici) as a Headers. */
export function fromFetchHeaders(headers: globalThis.Headers): Headers {
  return {
    get(name: string): string | undefined {
      return headers.get(name) ?? undefined;
    },
  };
}

/** RequestLike is the sliver of an express request the middleware touches. */
export interface RequestLike {
  headers: Record<string, string | string[] | undefined>;
  identity?: Identity;
}

/** ResponseLike is the sliver of an express response the middleware touches. */
export interface ResponseLike {
  status(code: number): ResponseLike;
  json(body: unknown): unknown;
}

/** NextFn is express's `next`. */
export type NextFn = (err?: unknown) => void;

/** Middleware is the express-style handler shape returned by the helpers. */
export type Middleware = (req: RequestLike, res: ResponseLike, next: NextFn) => void;

/**
 * middleware authenticates the caller, attaches the Identity as `req.identity`,
 * and rejects anyone without a valid credential with 401.
 */
export function middleware(auth: Authenticator): Middleware {
  return (req, res, next) => {
    void authenticateThen(auth, req, res, next);
  };
}

/**
 * requireRoles authenticates and additionally requires at least one of the roles
 * (403 otherwise). Role checks are skipped when the authenticator is disabled
 * (local development).
 */
export function requireRoles(auth: Authenticator, ...roles: string[]): Middleware {
  return (req, res, next) => {
    void authenticateThen(auth, req, res, next, roles);
  };
}

async function authenticateThen(
  auth: Authenticator,
  req: RequestLike,
  res: ResponseLike,
  next: NextFn,
  roles?: string[],
): Promise<void> {
  let identity: Identity;
  try {
    identity = await auth.authenticate(fromNodeHeaders(req.headers));
  } catch (err) {
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
function sendAuthError(res: ResponseLike, err: unknown): void {
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
