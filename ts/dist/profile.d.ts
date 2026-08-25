import type { Authenticator } from "./identity.js";
import { type CreateVerifierOptions } from "./verify.js";
/** Extra options a caller can pass alongside a profile without repeating the issuer. */
export type ProfileOptions = Omit<CreateVerifierOptions, "issuer">;
/**
 * oauth2ProxyOIDC is the fleet's default profile: verify the access token
 * oauth2-proxy forwards, against the given issuer, mapping the rbac-mapper
 * "groups" claim to roles, with userinfo fallback for display names.
 *
 * Any option (audience, claims, a testability seam) can be overridden via
 * `opts`; the issuer and the source/userinfo defaults are what the preset fills
 * in.
 */
export declare function oauth2ProxyOIDC(issuer: string, opts?: ProfileOptions): Promise<Authenticator>;
//# sourceMappingURL=profile.d.ts.map