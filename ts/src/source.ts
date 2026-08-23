// Token sources — pull a raw (still-encoded) token out of a request's headers.
//
// A TokenSource is a plain function so composing them (chain) and adapting a
// framework needs no classes. The header names below are the ones the fleet's
// gateway (oauth2-proxy) sets, plus Authorization; every one is overridable.

import type { Headers } from "./identity.js";

/**
 * HEADER carries the header names oauth2-proxy sets, plus Authorization.
 * Lookups are case-insensitive, so the canonical casing here is cosmetic.
 */
export const HEADER = {
  /**
   * accessToken carries the verified access token oauth2-proxy forwards
   * (set_xauthrequest + pass_access_token). Not "Bearer"-prefixed.
   */
  accessToken: "x-auth-request-access-token",
  /** user / email / groups are oauth2-proxy's pre-parsed identity headers — trust mode only. */
  user: "x-auth-request-user",
  email: "x-auth-request-email",
  groups: "x-auth-request-groups",
  /** authorization is the standard bearer header, for direct API callers and tests. */
  authorization: "authorization",
} as const;

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
export function headerSource(name: string, scheme?: string): TokenSource {
  return (headers) => {
    const value = (headers.get(name) ?? "").trim();
    if (value === "") {
      return undefined;
    }

    if (!scheme) {
      return value;
    }

    const prefix = scheme + " ";
    if (value.length < prefix.length || value.slice(0, prefix.length).toLowerCase() !== prefix.toLowerCase()) {
      return undefined;
    }

    const token = value.slice(prefix.length).trim();

    return token === "" ? undefined : token;
  };
}

/** chain tries each source in order and returns the first token found. */
export function chain(...sources: TokenSource[]): TokenSource {
  return (headers) => {
    for (const source of sources) {
      const raw = source(headers);
      if (raw !== undefined) {
        return raw;
      }
    }

    return undefined;
  };
}

/** oauth2ProxyAccessToken reads the access token oauth2-proxy injects. */
export function oauth2ProxyAccessToken(): TokenSource {
  return headerSource(HEADER.accessToken);
}

/** authorizationBearer reads a bearer token from the Authorization header. */
export function authorizationBearer(): TokenSource {
  return headerSource(HEADER.authorization, "Bearer");
}

/**
 * defaultSource tries the oauth2-proxy header first, then Authorization —
 * covering both a gateway-fronted request and a direct API caller.
 */
export function defaultSource(): TokenSource {
  return chain(oauth2ProxyAccessToken(), authorizationBearer());
}

/**
 * splitAndTrim splits on sep and drops empty/whitespace entries — for the
 * comma-separated groups header.
 */
export function splitAndTrim(value: string, sep: string): string[] {
  return value
    .split(sep)
    .map((part) => part.trim())
    .filter((part) => part !== "");
}
