// The verifying Authenticator (default, recommended mode) and the header-trust
// Authenticator (opt-in, no verification).
//
// Verification uses the `jose` library: createRemoteJWKSet fetches and caches
// the issuer's key set and rotates it on kid misses, and jwtVerify checks the
// signature, issuer, audience and expiry. jose owns the JWKS caching/rotation
// that keyset.go implements by hand in Go.
import { createRemoteJWKSet, jwtVerify } from "jose";
import { consoleLogger, InvalidTokenError, NoCredentialError, } from "./identity.js";
import { claimsMapper, identityFromClaims } from "./claims.js";
import { defaultSource, HEADER, splitAndTrim } from "./source.js";
import { discover } from "./discovery.js";
import { UserinfoFetcher } from "./userinfo.js";
class Verifier {
    keys;
    source;
    mapper;
    issuer;
    audience;
    logger;
    userinfo;
    constructor(keys, source, mapper, issuer, audience, logger, userinfo) {
        this.keys = keys;
        this.source = source;
        this.mapper = mapper;
        this.issuer = issuer;
        this.audience = audience;
        this.logger = logger;
        this.userinfo = userinfo;
    }
    enabled() {
        return true;
    }
    async authenticate(headers) {
        const raw = this.source(headers);
        if (raw === undefined) {
            throw new NoCredentialError();
        }
        let payload;
        try {
            // An empty audience accepts any token this issuer minted — right behind a
            // gateway that already checked it.
            const opts = {
                issuer: this.issuer,
                ...(this.audience ? { audience: this.audience } : {}),
            };
            // Branch so each jwtVerify overload (a dynamic getKey vs. a bare key) sees
            // the argument shape it declares.
            const result = typeof this.keys === "function"
                ? await jwtVerify(raw, this.keys, opts)
                : await jwtVerify(raw, this.keys, opts);
            payload = result.payload;
        }
        catch (err) {
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
export async function createVerifier(opts) {
    if (!opts.issuer) {
        throw new Error("gatewayauth: issuer is required");
    }
    const logger = opts.logger ?? consoleLogger;
    const source = opts.source ?? defaultSource();
    const mapper = claimsMapper(opts.claims);
    const fetchImpl = opts.fetch ?? fetch;
    let endpoints;
    if (opts.endpoints) {
        endpoints = { jwksUri: opts.endpoints.jwksUri ?? "", userinfoUri: opts.endpoints.userinfoUri ?? "" };
    }
    else if (opts.jwks) {
        endpoints = { jwksUri: "", userinfoUri: "" };
    }
    else {
        endpoints = await discover(opts.issuer, fetchImpl);
    }
    const keys = opts.jwks ?? createRemoteJWKSet(new URL(endpoints.jwksUri));
    let userinfo;
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
export function headerTrust() {
    return {
        enabled: () => true,
        authenticate: (headers) => {
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
//# sourceMappingURL=verify.js.map