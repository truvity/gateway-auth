import type { Identity } from "./identity.js";
/**
 * ClaimsMapper names the claims an Identity is built from. The defaults use the
 * OIDC-standard names with "groups" for roles — the fleet's rbac-mapper claim.
 * Another provider can point rolesClaim at "roles" or "realm_access".
 */
export interface ClaimsMapper {
    nameClaim: string;
    emailClaim: string;
    rolesClaim: string;
}
/**
 * claimsMapper returns a fully-defaulted ClaimsMapper. The zero/omitted value
 * uses the OIDC-standard names with "groups" for roles.
 */
export declare function claimsMapper(opts?: Partial<ClaimsMapper>): ClaimsMapper;
/**
 * identityFromClaims reads the claims a service cares about off a verified
 * token's payload.
 *
 * Claims are read one at a time rather than into a struct, because the roles
 * claim is named by configuration and because providers disagree about whether
 * a single group arrives as a string or a one-element array.
 */
export declare function identityFromClaims(mapper: ClaimsMapper, payload: Record<string, unknown>, raw: string): Identity;
//# sourceMappingURL=claims.d.ts.map