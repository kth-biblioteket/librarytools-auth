import { SignJWT, importPKCS8, exportJWK, calculateJwkThumbprint } from "jose";
import type { KeyLike, JWK } from "jose";

/**
 * Signs the shared identity token every Librarytools app (bookingtools
 * today, others later) verifies locally via this service's JWKS endpoint —
 * see the plan's "Identitets-JWT-kontraktet" section. EdDSA (Ed25519) so
 * only this service ever holds the private key; consumers never need a
 * shared secret, only the public JWKS.
 */

const ALG = "EdDSA";
const TOKEN_TTL_SECONDS = 60;

let privateKeyPromise: Promise<KeyLike> | null = null;
let jwkPromise: Promise<JWK & { kid: string; alg: string; use: string }> | null = null;

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is not set — identity signing is not configured.`);
  }
  return value;
}

function getPrivateKey(): Promise<KeyLike> {
  if (!privateKeyPromise) {
    const pem = requireEnv("AUTH_SIGNING_PRIVATE_KEY").replace(/\\n/g, "\n");
    privateKeyPromise = importPKCS8(pem, ALG) as Promise<KeyLike>;
  }
  return privateKeyPromise;
}

/** The public JWK, published at GET /mrbs/.well-known/jwks.json for
 * consumers to verify tokens against — recomputed once per process. */
async function getPublicJwk() {
  if (!jwkPromise) {
    jwkPromise = (async () => {
      const privateKey = await getPrivateKey();
      const jwk = await exportJWK(privateKey);
      const kid = await calculateJwkThumbprint(jwk);
      return { ...jwk, d: undefined, kid, alg: ALG, use: "sig" } as JWK & { kid: string; alg: string; use: string };
    })();
  }
  return jwkPromise;
}

export async function getJwks() {
  const jwk = await getPublicJwk();
  // Never leak the private "d" component — exportJWK on a private key
  // includes it; strip it explicitly for the published JWKS.
  const { d: _privateComponent, ...publicJwk } = jwk as JWK & { d?: string };
  void _privateComponent;
  return { keys: [publicJwk] };
}

export type IdentityClaims = {
  sub: string;
  email: string;
  name: string;
  isGroupAdmin: boolean;
};

/** audience is the origin of the app the token is handed to, so a token
 * delivered to one app can't be replayed against another. */
export async function signIdentityToken(
  claims: IdentityClaims,
  issuer: string,
  audience: string
): Promise<string> {
  const privateKey = await getPrivateKey();
  const jwk = await getPublicJwk();

  return new SignJWT({ email: claims.email, name: claims.name, isGroupAdmin: claims.isGroupAdmin })
    .setProtectedHeader({ alg: ALG, kid: jwk.kid })
    .setSubject(claims.sub)
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime(`${TOKEN_TTL_SECONDS}s`)
    .sign(privateKey);
}
