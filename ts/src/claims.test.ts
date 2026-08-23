import { describe, expect, it } from "vitest";

import { claimsMapper, identityFromClaims } from "./claims.js";
import { hasAnyRole, hasRole } from "./identity.js";

describe("claimsMapper", () => {
  it("defaults to OIDC-standard names with groups for roles", () => {
    expect(claimsMapper()).toEqual({
      nameClaim: "name",
      emailClaim: "email",
      rolesClaim: "groups",
    });
  });

  it("overrides only the named claims", () => {
    expect(claimsMapper({ rolesClaim: "realm_access" })).toEqual({
      nameClaim: "name",
      emailClaim: "email",
      rolesClaim: "realm_access",
    });
  });
});

describe("identityFromClaims", () => {
  it("maps standard claims and keeps the full claim set", () => {
    const identity = identityFromClaims(
      claimsMapper(),
      { sub: "u1", name: "Ada", email: "ada@x", groups: ["ops", "dev"], tenant: "t1" },
      "raw-token",
    );

    expect(identity).toEqual({
      subject: "u1",
      name: "Ada",
      email: "ada@x",
      roles: ["ops", "dev"],
      token: "raw-token",
      claims: { sub: "u1", name: "Ada", email: "ada@x", groups: ["ops", "dev"], tenant: "t1" },
    });
  });

  it("accepts a single role delivered as a bare string", () => {
    const identity = identityFromClaims(claimsMapper(), { sub: "u1", groups: "solo" }, "t");
    expect(identity.roles).toEqual(["solo"]);
  });

  it("drops non-string entries and non-array/string role claims", () => {
    expect(identityFromClaims(claimsMapper(), { groups: [1, "ok", null] }, "t").roles).toEqual(["ok"]);
    expect(identityFromClaims(claimsMapper(), { groups: 42 }, "t").roles).toEqual([]);
    expect(identityFromClaims(claimsMapper(), {}, "t").roles).toEqual([]);
  });

  it("reads roles from a configured claim name", () => {
    const identity = identityFromClaims(
      claimsMapper({ rolesClaim: "roles", nameClaim: "display" }),
      { sub: "u1", display: "Grace", roles: ["admin"] },
      "t",
    );
    expect(identity.name).toBe("Grace");
    expect(identity.roles).toEqual(["admin"]);
  });

  it("yields empty strings for absent or non-string display claims", () => {
    const identity = identityFromClaims(claimsMapper(), { sub: "u1", name: 5 }, "t");
    expect(identity.name).toBe("");
    expect(identity.email).toBe("");
  });
});

describe("hasRole / hasAnyRole", () => {
  const identity = identityFromClaims(claimsMapper(), { sub: "u1", groups: ["a", "b"] }, "t");

  it("checks exact role membership", () => {
    expect(hasRole(identity, "a")).toBe(true);
    expect(hasRole(identity, "c")).toBe(false);
  });

  it("checks any-of membership", () => {
    expect(hasAnyRole(identity, "c", "b")).toBe(true);
    expect(hasAnyRole(identity, "c", "d")).toBe(false);
    expect(hasAnyRole(identity)).toBe(false);
  });
});
