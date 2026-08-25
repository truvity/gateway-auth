import type { Identity, Logger } from "./identity.js";
import type { FetchLike } from "./discovery.js";
/**
 * userinfoTTL bounds how long a userinfo answer is reused. Names change rarely;
 * an hour keeps the endpoint out of the request path without making a rename
 * invisible for the workday.
 */
export declare const userinfoTTL: number;
/** UserinfoFetcher fills display claims from the provider's userinfo endpoint. */
export declare class UserinfoFetcher {
    private readonly uri;
    private readonly logger;
    private readonly fetchImpl;
    private readonly now;
    private readonly cache;
    constructor(uri: string, logger: Logger, fetchImpl?: FetchLike, now?: () => number);
    /**
     * fill sets identity.name/email from userinfo, mutating `identity` in place.
     * Failures only log — display claims are never worth failing a request over.
     */
    fill(accessToken: string, identity: Identity): Promise<void>;
}
//# sourceMappingURL=userinfo.d.ts.map