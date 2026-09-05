import { describe, expect, it } from "vitest";
import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair, type JWK, type KeyInput } from "jose";

import type { Headers } from "./identity.js";
import { InvalidTokenError, NoCredentialError } from "./identity.js";
import { createVerifier, headerTrust } from "./verify.js";
import { oauth2ProxyOIDC } from "./profile.js";
import { HEADER } from "./source.js";

const ISSUER = "https://issuer.example";

function headersOf(map: Record<string, string>): Headers {
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(map)) {
    lower[k.toLowerCase()] = v;
  }

  return { get: (name) => lower[name.toLowerCase()] };
}

async function keys() {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  return { publicKey, privateKey };
}

async function signToken(
  privateKey: KeyInput,
  claims: Record<string, unknown>,
  opts: { issuer?: string; audience?: string } = {},
): Promise<string> {
  const jwt = new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256" })
    .setIssuer(opts.issuer ?? ISSUER)
    .setIssuedAt()
    .setExpirationTime("1h");
  if (opts.audience) {
    jwt.setAudience(opts.audience);
  }

  return jwt.sign(privateKey);
}

describe("createVerifier (jwks seam)", () => {
  it("verifies a forwarded access token and maps claims", async () => {
    const { publicKey, privateKey } = await keys();
    const token = await signToken(privateKey, {
      sub: "u1",
      name: "Ada",
      email: "ada@x",
      groups: ["ops"],
    });

    const auth = await createVerifier({ issuer: ISSUER, jwks: publicKey });
    expect(auth.enabled()).toBe(true);

    const identity = await auth.authenticate(headersOf({ [HEADER.accessToken]: token }));
    expect(identity.subject).toBe("u1");
    expect(identity.name).toBe("Ada");
    expect(identity.email).toBe("ada@x");
    expect(identity.roles).toEqual(["ops"]);
    expect(identity.token).toBe(token);
  });

  it("also reads a bearer token from Authorization", async () => {
    const { publicKey, privateKey } = await keys();
    const token = await signToken(privateKey, { sub: "u1", groups: "ops" });
    const auth = await createVerifier({ issuer: ISSUER, jwks: publicKey });

    const identity = await auth.authenticate(headersOf({ authorization: `Bearer ${token}` }));
    expect(identity.subject).toBe("u1");
    expect(identity.roles).toEqual(["ops"]);
  });

  it("throws NoCredentialError when no token is present", async () => {
    const { publicKey } = await keys();
    const auth = await createVerifier({ issuer: ISSUER, jwks: publicKey });
    await expect(auth.authenticate(headersOf({}))).rejects.toBeInstanceOf(NoCredentialError);
  });

  it("throws InvalidTokenError for a wrong issuer", async () => {
    const { publicKey, privateKey } = await keys();
    const token = await signToken(privateKey, { sub: "u1" }, { issuer: "https://evil.example" });
    const auth = await createVerifier({ issuer: ISSUER, jwks: publicKey, logger: { warn() {} } });
    await expect(
      auth.authenticate(headersOf({ [HEADER.accessToken]: token })),
    ).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it("throws InvalidTokenError for a bad signature", async () => {
    const signer = await keys();
    const other = await keys();
    const token = await signToken(signer.privateKey, { sub: "u1" });
    const auth = await createVerifier({ issuer: ISSUER, jwks: other.publicKey, logger: { warn() {} } });
    await expect(
      auth.authenticate(headersOf({ [HEADER.accessToken]: token })),
    ).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it("enforces audience when configured", async () => {
    const { publicKey, privateKey } = await keys();
    const good = await signToken(privateKey, { sub: "u1" }, { audience: "svc" });
    const bad = await signToken(privateKey, { sub: "u1" }, { audience: "other" });
    const auth = await createVerifier({
      issuer: ISSUER,
      audience: "svc",
      jwks: publicKey,
      logger: { warn() {} },
    });

    await expect(auth.authenticate(headersOf({ [HEADER.accessToken]: good }))).resolves.toMatchObject({
      subject: "u1",
    });
    await expect(
      auth.authenticate(headersOf({ [HEADER.accessToken]: bad })),
    ).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it("verifies through a createLocalJWKSet resolver", async () => {
    const { publicKey, privateKey } = await keys();
    const jwk = (await exportJWK(publicKey)) as JWK;
    jwk.kid = "test";
    jwk.alg = "RS256";
    const resolver = createLocalJWKSet({ keys: [jwk] });
    const token = await new SignJWT({ sub: "u1", groups: ["ops"] })
      .setProtectedHeader({ alg: "RS256", kid: "test" })
      .setIssuer(ISSUER)
      .setExpirationTime("1h")
      .sign(privateKey);

    const auth = await createVerifier({ issuer: ISSUER, jwks: resolver });
    const identity = await auth.authenticate(headersOf({ [HEADER.accessToken]: token }));
    expect(identity.roles).toEqual(["ops"]);
  });
});

describe("userinfo fallback", () => {
  it("fills name/email from the userinfo endpoint when the token lacks them", async () => {
    const { publicKey, privateKey } = await keys();
    const token = await signToken(privateKey, { sub: "u1", groups: ["ops"] });

    let calls = 0;
    const fakeFetch: typeof fetch = async (input, init) => {
      calls += 1;
      const auth = new global.Headers(init?.headers).get("authorization");
      expect(auth).toBe(`Bearer ${token}`);
      expect(String(input)).toBe("https://issuer.example/userinfo");
      return new Response(JSON.stringify({ sub: "u1", name: "Ada", email: "ada@x" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };

    const auth = await createVerifier({
      issuer: ISSUER,
      jwks: publicKey,
      userinfoFallback: true,
      endpoints: { userinfoUri: "https://issuer.example/userinfo" },
      fetch: fakeFetch,
    });

    const first = await auth.authenticate(headersOf({ [HEADER.accessToken]: token }));
    expect(first.name).toBe("Ada");
    expect(first.email).toBe("ada@x");

    // Second call for the same subject is served from cache.
    await auth.authenticate(headersOf({ [HEADER.accessToken]: token }));
    expect(calls).toBe(1);
  });

  it("ignores a userinfo answer for a different subject", async () => {
    const { publicKey, privateKey } = await keys();
    const token = await signToken(privateKey, { sub: "u1", groups: ["ops"] });
    const fakeFetch: typeof fetch = async () =>
      new Response(JSON.stringify({ sub: "someone-else", name: "Mallory" }), { status: 200 });

    const auth = await createVerifier({
      issuer: ISSUER,
      jwks: publicKey,
      userinfoFallback: true,
      endpoints: { userinfoUri: "https://issuer.example/userinfo" },
      fetch: fakeFetch,
    });

    const identity = await auth.authenticate(headersOf({ [HEADER.accessToken]: token }));
    expect(identity.name).toBe("");
  });
});

describe("createVerifier discovery", () => {
  it("runs OIDC discovery and rejects a mismatched issuer", async () => {
    const fakeFetch: typeof fetch = async (input) => {
      expect(String(input)).toBe("https://issuer.example/.well-known/openid-configuration");
      return new Response(
        JSON.stringify({ issuer: "https://someone-else.example", jwks_uri: "https://x/jwks" }),
        { status: 200 },
      );
    };
    await expect(createVerifier({ issuer: ISSUER, fetch: fakeFetch })).rejects.toThrow(/declares issuer/);
  });

  it("requires an issuer", async () => {
    await expect(createVerifier({ issuer: "" })).rejects.toThrow(/issuer is required/);
  });
});

describe("oauth2ProxyOIDC preset", () => {
  it("verifies with userinfo fallback on by default and honours overrides", async () => {
    const { publicKey, privateKey } = await keys();
    const token = await signToken(privateKey, { sub: "u1", roles: ["admin"] });
    const auth = await oauth2ProxyOIDC(ISSUER, {
      jwks: publicKey,
      claims: { rolesClaim: "roles" },
    });
    const identity = await auth.authenticate(headersOf({ [HEADER.accessToken]: token }));
    expect(identity.roles).toEqual(["admin"]);
  });
});

describe("headerTrust", () => {
  it("builds an identity from oauth2-proxy identity headers without verifying", async () => {
    const auth = headerTrust();
    expect(auth.enabled()).toBe(true);
    const identity = await auth.authenticate(
      headersOf({
        [HEADER.user]: "u1",
        [HEADER.email]: "ada@x",
        [HEADER.groups]: "ops, dev",
        [HEADER.accessToken]: "opaque",
      }),
    );
    expect(identity).toMatchObject({
      subject: "u1",
      name: "u1",
      email: "ada@x",
      roles: ["ops", "dev"],
      token: "opaque",
    });
  });

  it("falls back to email for the display name when user is absent", async () => {
    const identity = await headerTrust().authenticate(headersOf({ [HEADER.email]: "ada@x" }));
    expect(identity.name).toBe("ada@x");
  });

  it("rejects a request that bypassed the proxy", async () => {
    await expect(headerTrust().authenticate(headersOf({}))).rejects.toBeInstanceOf(NoCredentialError);
  });
});
