// Userinfo fallback — fill display claims (name, email) from the provider's
// userinfo endpoint, authenticating with the caller's own already-verified
// access token. Answers are cached per subject.
//
// Zitadel asserts profile claims into the ID token, not the access token, so an
// access-token-only identity can lack name/email. Failures only degrade
// display — they never fail a request.

import type { Identity, Logger } from "./identity.js";
import type { FetchLike } from "./discovery.js";

/**
 * userinfoTTL bounds how long a userinfo answer is reused. Names change rarely;
 * an hour keeps the endpoint out of the request path without making a rename
 * invisible for the workday.
 */
export const userinfoTTL = 60 * 60 * 1000;

interface UserinfoEntry {
  name: string;
  email: string;
  fetchedAt: number;
}

/** UserinfoFetcher fills display claims from the provider's userinfo endpoint. */
export class UserinfoFetcher {
  private readonly cache = new Map<string, UserinfoEntry>();

  constructor(
    private readonly uri: string,
    private readonly logger: Logger,
    private readonly fetchImpl: FetchLike = fetch,
    private readonly now: () => number = Date.now,
  ) {}

  /**
   * fill sets identity.name/email from userinfo, mutating `identity` in place.
   * Failures only log — display claims are never worth failing a request over.
   */
  async fill(accessToken: string, identity: Identity): Promise<void> {
    const cached = this.cache.get(identity.subject);
    if (cached && this.now() - cached.fetchedAt < userinfoTTL) {
      identity.name = cached.name;
      identity.email = cached.email;

      return;
    }

    let response: Response;
    try {
      response = await this.fetchImpl(this.uri, {
        headers: { authorization: `Bearer ${accessToken}` },
      });
    } catch (err) {
      this.logger.warn("userinfo request failed", { error: String(err) });

      return;
    }

    if (!response.ok) {
      this.logger.warn("userinfo refused", { status: response.status });

      return;
    }

    let body: { sub?: string; name?: string; email?: string };
    try {
      body = (await response.json()) as { sub?: string; name?: string; email?: string };
    } catch (err) {
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
