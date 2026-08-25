/** discoveryTimeout bounds the one startup call to the provider. */
export declare const discoveryTimeout = 15000;
/** FetchLike is the subset of the fetch API this package uses; injectable for tests. */
export type FetchLike = typeof fetch;
/** Endpoints is what this package needs from the provider's discovery document. */
export interface Endpoints {
    jwksUri: string;
    userinfoUri: string;
}
/** discover reads the provider's OpenID configuration. */
export declare function discover(issuer: string, fetchImpl?: FetchLike): Promise<Endpoints>;
//# sourceMappingURL=discovery.d.ts.map