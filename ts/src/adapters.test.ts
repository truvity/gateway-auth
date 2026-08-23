import { describe, expect, it } from "vitest";

import type { Authenticator, Identity } from "./identity.js";
import { InvalidTokenError, NoCredentialError, disabled } from "./identity.js";
import {
  fromFetchHeaders,
  fromNodeHeaders,
  middleware,
  requireRoles,
  type ResponseLike,
} from "./adapters.js";
import { HEADER } from "./source.js";

describe("fromNodeHeaders", () => {
  it("looks names up case-insensitively and joins array values", () => {
    const h = fromNodeHeaders({ "x-auth-request-user": "u1", "x-multi": ["a", "b"] });
    expect(h.get("X-Auth-Request-User")).toBe("u1");
    expect(h.get("x-multi")).toBe("a, b");
    expect(h.get("absent")).toBeUndefined();
  });
});

describe("fromFetchHeaders", () => {
  it("wraps a WHATWG Headers", () => {
    const h = fromFetchHeaders(new Headers({ authorization: "Bearer t" }));
    expect(h.get("Authorization")).toBe("Bearer t");
    expect(h.get("absent")).toBeUndefined();
  });
});

// A fake authenticator that yields a fixed identity or throws a chosen error.
function fakeAuth(result: Identity | Error, enabled = true): Authenticator {
  return {
    enabled: () => enabled,
    authenticate: () => (result instanceof Error ? Promise.reject(result) : Promise.resolve(result)),
  };
}

const identity: Identity = {
  subject: "u1",
  name: "Ada",
  email: "ada@x",
  roles: ["ops"],
  token: "t",
  claims: {},
};

function fakeRes(): ResponseLike & { code?: number; body?: unknown } {
  const res: ResponseLike & { code?: number; body?: unknown } = {
    status(code: number) {
      res.code = code;
      return res;
    },
    json(body: unknown) {
      res.body = body;
      return res;
    },
  };

  return res;
}

async function run(
  mw: (req: any, res: any, next: any) => void,
  headers: Record<string, string | string[] | undefined>,
): Promise<{ req: any; res: ReturnType<typeof fakeRes>; nextCalled: boolean }> {
  const req: any = { headers };
  const res = fakeRes();
  let nextCalled = false;
  mw(req, res, () => {
    nextCalled = true;
  });
  // Let the middleware's async work settle.
  await new Promise((r) => setImmediate(r));

  return { req, res, nextCalled };
}

describe("middleware", () => {
  it("attaches req.identity and calls next on success", async () => {
    const { req, nextCalled } = await run(middleware(fakeAuth(identity)), {
      [HEADER.accessToken]: "t",
    });
    expect(nextCalled).toBe(true);
    expect(req.identity).toEqual(identity);
  });

  it("401s NoCredentialError", async () => {
    const { res, nextCalled } = await run(middleware(fakeAuth(new NoCredentialError())), {});
    expect(nextCalled).toBe(false);
    expect(res.code).toBe(401);
  });

  it("401s InvalidTokenError", async () => {
    const { res } = await run(middleware(fakeAuth(new InvalidTokenError())), {});
    expect(res.code).toBe(401);
  });
});

describe("requireRoles", () => {
  it("calls next when the identity holds a required role", async () => {
    const { req, nextCalled } = await run(requireRoles(fakeAuth(identity), "ops"), {});
    expect(nextCalled).toBe(true);
    expect(req.identity).toEqual(identity);
  });

  it("403s when the identity holds none of the required roles", async () => {
    const { res, nextCalled } = await run(requireRoles(fakeAuth(identity), "admin"), {});
    expect(nextCalled).toBe(false);
    expect(res.code).toBe(403);
  });

  it("skips the role check when the authenticator is disabled", async () => {
    const { nextCalled, res } = await run(requireRoles(disabled(), "admin"), {});
    expect(nextCalled).toBe(true);
    expect(res.code).toBeUndefined();
  });

  it("401s before the role check when authentication fails", async () => {
    const { res } = await run(requireRoles(fakeAuth(new NoCredentialError()), "ops"), {});
    expect(res.code).toBe(401);
  });
});
