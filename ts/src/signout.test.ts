import { describe, expect, it } from "vitest";

import { signOutUrl } from "./signout.js";

describe("signOutUrl", () => {
  it("defaults the proxy prefix to /oauth2", () => {
    expect(signOutUrl()).toBe("/oauth2/sign_out");
  });

  it("honors a custom prefix and normalizes slashes", () => {
    expect(signOutUrl("_gwauth")).toBe("/_gwauth/sign_out");
    expect(signOutUrl("/_gwauth/")).toBe("/_gwauth/sign_out");
  });

  it("adds the redirect as rd", () => {
    expect(signOutUrl("/oauth2", "/")).toBe("/oauth2/sign_out?rd=%2F");
  });
});
