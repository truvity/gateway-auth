// OIDC discovery — read the provider's OpenID configuration for the two fields
// this package needs: the JWKS URI and the userinfo endpoint.
//
// Discovery is done by hand rather than with an OIDC relying-party library: this
// package is not a relying party. It never runs a code flow, holds no client
// credentials and mints no sessions — it verifies a token somebody else
// obtained and, for display claims the access token omits, asks userinfo. One
// well-known document and two fields is the whole requirement.

/** discoveryTimeout bounds the one startup call to the provider. */
export const discoveryTimeout = 15_000;

/** FetchLike is the subset of the fetch API this package uses; injectable for tests. */
export type FetchLike = typeof fetch;

/** Endpoints is what this package needs from the provider's discovery document. */
export interface Endpoints {
  jwksUri: string;
  userinfoUri: string;
}

/** discover reads the provider's OpenID configuration. */
export async function discover(issuer: string, fetchImpl: FetchLike = fetch): Promise<Endpoints> {
  const wellKnown = issuer.replace(/\/$/, "") + "/.well-known/openid-configuration";

  let response: Response;
  try {
    response = await fetchImpl(wellKnown, { signal: AbortSignal.timeout(discoveryTimeout) });
  } catch (err) {
    throw new Error(`gatewayauth: fetch ${wellKnown}`, { cause: err });
  }

  if (!response.ok) {
    throw new Error(`gatewayauth: fetch ${wellKnown}: unexpected status ${response.status}`);
  }

  const document = (await response.json()) as {
    issuer?: string;
    jwks_uri?: string;
    userinfo_endpoint?: string;
  };

  // The issuer must match what we were configured with, or a redirect to
  // somebody else's provider would silently hand them the service.
  if (document.issuer !== issuer) {
    throw new Error(
      `gatewayauth: discovery at ${wellKnown} declares issuer ${String(document.issuer)}, want ${issuer}`,
    );
  }

  if (!document.jwks_uri) {
    throw new Error(`gatewayauth: discovery at ${wellKnown} declares no jwks_uri`);
  }

  return { jwksUri: document.jwks_uri, userinfoUri: document.userinfo_endpoint ?? "" };
}
