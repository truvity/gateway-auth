// Claims mapping — names the claims an Identity is built from, and reads them
// off a verified token's payload.

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
export function claimsMapper(opts?: Partial<ClaimsMapper>): ClaimsMapper {
  return {
    nameClaim: opts?.nameClaim || "name",
    emailClaim: opts?.emailClaim || "email",
    rolesClaim: opts?.rolesClaim || "groups",
  };
}

/**
 * identityFromClaims reads the claims a service cares about off a verified
 * token's payload.
 *
 * Claims are read one at a time rather than into a struct, because the roles
 * claim is named by configuration and because providers disagree about whether
 * a single group arrives as a string or a one-element array.
 */
export function identityFromClaims(
  mapper: ClaimsMapper,
  payload: Record<string, unknown>,
  raw: string,
): Identity {
  const subject = stringClaim(payload, "sub");

  return {
    subject,
    name: stringClaim(payload, mapper.nameClaim),
    email: stringClaim(payload, mapper.emailClaim),
    roles: claimValues(payload, mapper.rolesClaim),
    token: raw,
    // Materialize every claim, so a service can read app-specific ones (an
    // emp:{slug}, a tenant id) the typed fields do not cover.
    claims: { ...payload },
  };
}

function stringClaim(payload: Record<string, unknown>, name: string): string {
  const value = payload[name];

  return typeof value === "string" ? value : "";
}

/**
 * claimValues reads a claim that may be a string or an array of strings, and
 * returns nothing for anything else. Getting this wrong silently strips
 * everyone's role, so both shapes are handled explicitly.
 */
function claimValues(payload: Record<string, unknown>, name: string): string[] {
  const raw = payload[name];

  if (typeof raw === "string") {
    return [raw];
  }

  if (Array.isArray(raw)) {
    return raw.filter((item): item is string => typeof item === "string");
  }

  return [];
}
