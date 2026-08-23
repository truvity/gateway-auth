import { describe, expect, it } from "vitest";

import type { Headers } from "./identity.js";
import {
  authorizationBearer,
  chain,
  defaultSource,
  headerSource,
  oauth2ProxyAccessToken,
  splitAndTrim,
  HEADER,
} from "./source.js";

function headersOf(map: Record<string, string>): Headers {
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(map)) {
    lower[k.toLowerCase()] = v;
  }

  return { get: (name) => lower[name.toLowerCase()] };
}

describe("headerSource", () => {
  it("reads a header verbatim when no scheme is set", () => {
    const src = headerSource("x-token");
    expect(src(headersOf({ "x-token": "  abc  " }))).toBe("abc");
  });

  it("returns undefined for a missing or empty header", () => {
    const src = headerSource("x-token");
    expect(src(headersOf({}))).toBeUndefined();
    expect(src(headersOf({ "x-token": "   " }))).toBeUndefined();
  });

  it("strips a case-insensitive scheme and its trailing space", () => {
    const src = headerSource(HEADER.authorization, "Bearer");
    expect(src(headersOf({ authorization: "Bearer tok" }))).toBe("tok");
    expect(src(headersOf({ authorization: "bearer tok" }))).toBe("tok");
    expect(src(headersOf({ authorization: "BEARER   tok  " }))).toBe("tok");
  });

  it("rejects a value that lacks the required scheme", () => {
    const src = headerSource(HEADER.authorization, "Bearer");
    expect(src(headersOf({ authorization: "Basic tok" }))).toBeUndefined();
    expect(src(headersOf({ authorization: "Bearer" }))).toBeUndefined();
    expect(src(headersOf({ authorization: "Bearer   " }))).toBeUndefined();
  });
});

describe("chain / defaultSource", () => {
  it("returns the first source that yields a token", () => {
    const src = chain(headerSource("a"), headerSource("b"));
    expect(src(headersOf({ b: "second" }))).toBe("second");
    expect(src(headersOf({ a: "first", b: "second" }))).toBe("first");
    expect(src(headersOf({}))).toBeUndefined();
  });

  it("prefers the oauth2-proxy header over Authorization", () => {
    const src = defaultSource();
    expect(
      src(headersOf({ [HEADER.accessToken]: "proxy", authorization: "Bearer bear" })),
    ).toBe("proxy");
    expect(src(headersOf({ authorization: "Bearer bear" }))).toBe("bear");
  });

  it("oauth2ProxyAccessToken and authorizationBearer read their headers", () => {
    expect(oauth2ProxyAccessToken()(headersOf({ [HEADER.accessToken]: "t" }))).toBe("t");
    expect(authorizationBearer()(headersOf({ authorization: "Bearer t" }))).toBe("t");
  });
});

describe("splitAndTrim", () => {
  it("splits and drops empty/whitespace entries", () => {
    expect(splitAndTrim("a, b ,,c , ", ",")).toEqual(["a", "b", "c"]);
    expect(splitAndTrim("", ",")).toEqual([]);
  });
});
