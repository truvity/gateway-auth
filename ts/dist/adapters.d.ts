import { type Authenticator, type Headers, type Identity } from "./identity.js";
/**
 * fromNodeHeaders wraps node's `req.headers` (IncomingHttpHeaders) as a Headers.
 * Node lowercases header names already; a duplicated header arrives as an array
 * and is joined with ", " so a source still sees one value.
 */
export declare function fromNodeHeaders(headers: Record<string, string | string[] | undefined>): Headers;
/** fromFetchHeaders wraps a WHATWG Headers (fetch / hono / undici) as a Headers. */
export declare function fromFetchHeaders(headers: globalThis.Headers): Headers;
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
export declare function middleware(auth: Authenticator): Middleware;
/**
 * requireRoles authenticates and additionally requires at least one of the roles
 * (403 otherwise). Role checks are skipped when the authenticator is disabled
 * (local development).
 */
export declare function requireRoles(auth: Authenticator, ...roles: string[]): Middleware;
//# sourceMappingURL=adapters.d.ts.map