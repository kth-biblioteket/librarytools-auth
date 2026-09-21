import * as client from "openid-client";

/**
 * KTH login via Microsoft Entra ID (OpenID Connect, Authorization Code +
 * PKCE) against KTH's own ADFS. This service IS the registered app's
 * redirect_uri (https://apps.lib.kth.se/mrbs and the ref equivalent) — it
 * owns that literal path, so unlike when this code lived inside bookingtools,
 * no forwarding-from-the-app-root hack is needed: the callback is handled
 * directly where it lands (see index.ts's root route).
 */

let configPromise: Promise<client.Configuration> | null = null;

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is not set — KTH login is not configured.`);
  }
  return value;
}

/** Lazy, cached discovery — done once per process, not per request. */
function getOidcConfig(): Promise<client.Configuration> {
  if (!configPromise) {
    const issuer = requireEnv("OIDC_ISSUER");
    const clientId = requireEnv("OIDC_CLIENT_ID");
    const clientSecret = requireEnv("OIDC_CLIENT_SECRET");
    configPromise = client.discovery(new URL(issuer), clientId, clientSecret);
  }
  return configPromise;
}

/** The redirect_uri sent to Entra ID. This service's root literally *is* the
 * registered, fixed redirect_uri — no path to append. */
export function getRedirectUri(origin: string): string {
  return origin;
}

export type OidcRequest = {
  authorizationUrl: URL;
  state: string;
  nonce: string;
  codeVerifier: string;
};

export async function buildAuthorizationRequest(origin: string): Promise<OidcRequest> {
  const config = await getOidcConfig();
  const codeVerifier = client.randomPKCECodeVerifier();
  const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
  const state = client.randomState();
  const nonce = client.randomNonce();

  const authorizationUrl = client.buildAuthorizationUrl(config, {
    redirect_uri: getRedirectUri(origin),
    scope: "openid profile email",
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    state,
    nonce,
  });

  return { authorizationUrl, state, nonce, codeVerifier };
}

export type KthClaims = { sub: string; email: string; name: string };

export async function exchangeCodeForClaims(
  callbackUrl: URL,
  origin: string,
  checks: { state: string; nonce: string; codeVerifier: string }
): Promise<{ claims: KthClaims; accessToken: string }> {
  const config = await getOidcConfig();

  // authorizationCodeGrant() derives the redirect_uri it sends to the token
  // endpoint from the URL it's given (minus the query string) — build one
  // from the same fixed origin used for the authorization request, keeping
  // the real query string (code, state) so the response still parses.
  const grantUrl = new URL(getRedirectUri(origin));
  grantUrl.search = callbackUrl.search;

  const tokens = await client.authorizationCodeGrant(config, grantUrl, {
    pkceCodeVerifier: checks.codeVerifier,
    expectedState: checks.state,
    expectedNonce: checks.nonce,
  });

  const idTokenClaims = tokens.claims();
  if (!idTokenClaims) {
    throw new Error("KTH login response did not include an ID token.");
  }

  // KTH's Entra ID tenant may surface the address as `email` or, for some
  // account types, only as `preferred_username`.
  const email = (idTokenClaims.email ?? idTokenClaims.preferred_username) as string | undefined;
  const name = (idTokenClaims.name as string | undefined) ?? email;
  if (!email || !name) {
    throw new Error("KTH login response did not include an email/name claim.");
  }

  return {
    claims: { sub: String(idTokenClaims.sub), email, name },
    accessToken: tokens.access_token,
  };
}

/** Whether OIDC_ADMIN_GROUP_ID is configured — lets callers skip the Graph
 * call entirely (no network, no behavior change) when it isn't. */
export function isAdminGroupConfigured(): boolean {
  return Boolean(process.env.OIDC_ADMIN_GROUP_ID);
}

/** Checks KTH-group membership via Microsoft Graph. Only call when
 * isAdminGroupConfigured() is true. */
export async function checkIsGroupAdmin(accessToken: string): Promise<boolean> {
  const groupId = process.env.OIDC_ADMIN_GROUP_ID;
  if (!groupId) return false;

  const response = await fetch("https://graph.microsoft.com/v1.0/me/checkMemberGroups", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ groupIds: [groupId] }),
  });
  if (!response.ok) return false;

  const data = (await response.json()) as { value?: string[] };
  return (data.value ?? []).includes(groupId);
}
