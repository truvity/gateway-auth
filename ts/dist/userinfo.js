// Userinfo fallback — fill display claims (name, email) from the provider's
// userinfo endpoint, authenticating with the caller's own already-verified
// access token. Answers are cached per subject.
//
// Zitadel asserts profile claims into the ID token, not the access token, so an
// access-token-only identity can lack name/email. Failures only degrade
// display — they never fail a request.
/**
 * userinfoTTL bounds how long a userinfo answer is reused. Names change rarely;
 * an hour keeps the endpoint out of the request path without making a rename
 * invisible for the workday.
 */
export const userinfoTTL = 60 * 60 * 1000;
/** UserinfoFetcher fills display claims from the provider's userinfo endpoint. */
export class UserinfoFetcher {
    uri;
    logger;
    fetchImpl;
    now;
    cache = new Map();
    constructor(uri, logger, fetchImpl = fetch, now = Date.now) {
        this.uri = uri;
        this.logger = logger;
        this.fetchImpl = fetchImpl;
        this.now = now;
    }
    /**
     * fill sets identity.name/email from userinfo, mutating `identity` in place.
     * Failures only log — display claims are never worth failing a request over.
     */
    async fill(accessToken, identity) {
        const cached = this.cache.get(identity.subject);
        if (cached && this.now() - cached.fetchedAt < userinfoTTL) {
            identity.name = cached.name;
            identity.email = cached.email;
            return;
        }
        let response;
        try {
            response = await this.fetchImpl(this.uri, {
                headers: { authorization: `Bearer ${accessToken}` },
            });
        }
        catch (err) {
            this.logger.warn("userinfo request failed", { error: String(err) });
            return;
        }
        if (!response.ok) {
            this.logger.warn("userinfo refused", { status: response.status });
            return;
        }
        let body;
        try {
            body = (await response.json());
        }
        catch (err) {
            this.logger.warn("userinfo undecodable", { error: String(err) });
            return;
        }
        // The endpoint answered for whoever the token belongs to; require that to be
        // the caller before displaying anything.
        if (body.sub !== identity.subject) {
            return;
        }
        const name = body.name ?? "";
        const email = body.email ?? "";
        identity.name = name;
        identity.email = email;
        this.cache.set(identity.subject, { name, email, fetchedAt: this.now() });
    }
}
//# sourceMappingURL=userinfo.js.map