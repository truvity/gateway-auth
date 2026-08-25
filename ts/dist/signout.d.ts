/**
 * signOutUrl builds the oauth2-proxy sign-out URL. Pass the exposure's
 * proxyPrefix (default "/oauth2"); an optional redirectTo becomes the proxy's
 * `rd` parameter, honored when its domain is in the proxy's allow-list.
 */
export declare function signOutUrl(proxyPrefix?: string, redirectTo?: string): string;
//# sourceMappingURL=signout.d.ts.map