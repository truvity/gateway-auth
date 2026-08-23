// The verifying Authenticator (default, recommended mode) and the header-trust
// Authenticator (opt-in, no verification).
//
// Verification uses the `jose` library: createRemoteJWKSet fetches and caches
// the issuer's key set and rotates it on kid misses, and jwtVerify checks the
// signature, issuer, audience and expiry. jose owns the JWKS caching/rotation
// that keyset.go implements by hand in Go.

import { createRemoteJWKSet, jwtVerify } from "jose";
import type { JWK, JWTVerifyGetKey, JWTVerifyOptions, KeyLike } from "jose";

import {
  type Authenticator,
  type Headers,
  type Identity,
  type Logger,
  consoleLogger,
  InvalidTokenError,
  NoCredentialError,
} from "./identity.js";
import { type ClaimsMapper, claimsMapper, identityFromClaims } from "./claims.js";
import { type TokenSource, defaultSource, HEADER, splitAndTrim } from "./source.js";
import { type Endpoints, type FetchLike, discover } from "./discovery.js";
import { UserinfoFetcher } from "./userinfo.js";

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

  // --- Testability seams (all optional). ---

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

class Verifier implements Authenticator {
  constructor(
    private readonly keys: KeyResolver,
    private readonly source: TokenSource,
    private readonly mapper: ClaimsMapper,
    private readonly issuer: string,
    private readonly audience: string,
    private readonly logger: Logger,
    private readonly userinfo?: UserinfoFetcher,
  ) {}

  enabled(): boolean {
    return true;
  }

  async authenticate(headers: Headers): Promise<Identity> {
    const raw = this.source(headers);
    if (raw === undefined) {
      throw new NoCredentialError();
    }

    let payload: Record<string, unknown>;
    try {
      // An empty audience accepts any token this issuer minted — right behind a
      // gateway that already checked it.
      const opts: JWTVerifyOptions = {
        issuer: this.issuer,
        ...(this.audience ? { audience: this.audience } : {}),
      };
      // Branch so each jwtVerify overload (a dynamic getKey vs. a bare key) sees
      // the argument shape it declares.
      const result =
        typeof this.keys === "function"
          ? await jwtVerify(raw, this.keys, opts)
          : await jwtVerify(raw, this.keys, opts);
      payload = result.payload as Record<string, unknown>;
    } catch (err) {
      // The reason goes to the log, not the caller: telling an unauthenticated
      // client why its token failed helps it forge a better one.
      this.logger.warn("token rejected", { error: String(err) });

      throw new InvalidTokenError(undefined, { cause: err });
    }

    const identity = identityFromClaims(this.mapper, payload, raw);

    // An access-token-only identity can lack name/email. Ask userinfo with the
    // token that already proved itself. Failures only degrade display.
    if (this.userinfo && identity.name === "" && identity.email === "") {
      await this.userinfo.fill(raw, identity);
    }

    return identity;
  }
}

/**
 * createVerifier builds an Authenticator against the issuer's JWKS. Discovery
 * happens here (unless `endpoints`/`jwks` are injected), so an unreachable or
 * misconfigured issuer fails at startup rather than on the first request. The
 * remote JWKS itself is fetched lazily by jose on the first verification and
 * cached/rotated thereafter.
 */
export async function createVerifier(opts: CreateVerifierOptions): Promise<Authenticator> {
  if (!opts.issuer) {
    throw new Error("gatewayauth: issuer is required");
  }

  const logger = opts.logger ?? consoleLogger;
  const source = opts.source ?? defaultSource();
  const mapper = claimsMapper(opts.claims);
  const fetchImpl = opts.fetch ?? fetch;

  let endpoints: Endpoints;
  if (opts.endpoints) {
    endpoints = { jwksUri: opts.endpoints.jwksUri ?? "", userinfoUri: opts.endpoints.userinfoUri ?? "" };
  } else if (opts.jwks) {
    endpoints = { jwksUri: "", userinfoUri: "" };
  } else {
    endpoints = await discover(opts.issuer, fetchImpl);
  }

  const keys: KeyResolver = opts.jwks ?? createRemoteJWKSet(new URL(endpoints.jwksUri));

  let userinfo: UserinfoFetcher | undefined;
  if (opts.userinfoFallback && endpoints.userinfoUri) {
    userinfo = new UserinfoFetcher(endpoints.userinfoUri, logger, fetchImpl);
  }

  return new Verifier(keys, source, mapper, opts.issuer, opts.audience ?? "", logger, userinfo);
}

// ---------------------------------------------------------------------------
// Header trust — opt-in, no token verification.
// ---------------------------------------------------------------------------

/**
 * headerTrust returns an Authenticator that builds an Identity from
 * oauth2-proxy's pre-parsed identity headers WITHOUT verifying a token. For
 * surfaces where the ingress-from-fleet NetworkPolicy is genuinely the trust
 * boundary. It still requires the headers to be present, so a request that
 * bypassed the proxy is rejected. The verifying mode is the recommended default.
 */
export function headerTrust(): Authenticator {
  return {
    enabled: () => true,
    authenticate: (headers: Headers): Promise<Identity> => {
      const subject = headers.get(HEADER.user) ?? "";
      const email = headers.get(HEADER.email) ?? "";

      if (subject === "" && email === "") {
        return Promise.reject(new NoCredentialError());
      }

      const name = subject !== "" ? subject : email;

      return Promise.resolve({
        subject,
        name,
        email,
        roles: splitAndTrim(headers.get(HEADER.groups) ?? "", ","),
        token: headers.get(HEADER.accessToken) ?? "",
        claims: {},
      });
    },
  };
}
