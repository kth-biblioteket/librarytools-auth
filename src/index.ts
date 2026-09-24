import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import {
  buildAuthorizationRequest,
  exchangeCodeForClaims,
  isAdminGroupConfigured,
  checkIsGroupAdmin,
} from "./oidc.js";
import { signIdentityToken, getJwks } from "./jwt.js";
import { getExternalOrigin } from "./origin.js";

/**
 * The thin, rarely-deployed KTH ADFS login broker for the "Librarytools"
 * apps on apps.lib.kth.se. Owns the one fixed path the reused Entra
 * registration is allowed to redirect to (`/mrbs`) and nothing else — see
 * the plan at /Users/tholind/.claude/plans/vad-vi-beh-ver-r-zazzy-wombat.md.
 *
 * It never talks to any app's database. On a successful ADFS login it signs
 * a short-lived identity JWT (see jwt.ts), sets it as a domain-wide cookie,
 * and redirects the browser to `returnTo` — each consuming app (bookingtools
 * today, others later) verifies that token itself via GET /.well-known/jwks.json
 * and does its own local session/user provisioning.
 */

const OIDC_COOKIE_MAX_AGE = 60 * 10; // 10 minutes: long enough for the ADFS round trip, short enough to limit replay.
const IDENTITY_COOKIE_MAX_AGE = 60; // matches the identity JWT's own lifetime — single-use handoff, not a session.
const IDENTITY_COOKIE_NAME = "kth_identity";

const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN; // e.g. apps.lib.kth.se / apps-ref.lib.kth.se
// Fallbacks for when the calling app didn't say (no returnTo / errorTo) -
// deliberately not tied to any one app, since every app on the host shares
// this service.
const DEFAULT_RETURN_TO = process.env.DEFAULT_RETURN_TO ?? "/";
const LOGIN_ERROR_PATH = process.env.LOGIN_ERROR_PATH ?? "/mrbs/error";
// Not a fallback: /mrbs/* used to be bookingtools' own URLs, so old
// bookmarks are forwarded there.
const LEGACY_TARGET_PREFIX = process.env.LEGACY_TARGET_PREFIX ?? "/bookingtools";

const app = new Hono().basePath("/mrbs");

function oidcCookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax" as const,
    path: "/",
    maxAge: OIDC_COOKIE_MAX_AGE,
  };
}

/** Only a same-origin relative path is safe to carry through as returnTo —
 * any path on the shared domain is fine now (cross-app), just no
 * protocol-relative "//host" open-redirect trick. */
function safeReturnTo(value: string | undefined | null): string | null {
  if (!value) return null;
  return /^\/(?!\/)/.test(value) ? value : null;
}

function clearOidcCookies(c: Parameters<typeof deleteCookie>[0]) {
  for (const name of ["oidc_state", "oidc_nonce", "oidc_verifier", "oidc_return_to", "oidc_error_to"]) {
    deleteCookie(c, name, { path: "/" });
  }
}

/** Appends ?error=<code> to the calling app's own error page (errorTo),
 * falling back to LOGIN_ERROR_PATH when the app didn't give one. */
function errorRedirectPath(errorTo: string | null, error: "oidc_state" | "oidc_failed"): string {
  const path = errorTo ?? LOGIN_ERROR_PATH;
  return `${path}${path.includes("?") ? "&" : "?"}error=${error}`;
}

app.get("/login", async (c) => {
  const returnTo = safeReturnTo(c.req.query("returnTo"));
  // Each app's own login/error page, so a failed round trip lands back in
  // the app that started it rather than always in bookingtools.
  const errorTo = safeReturnTo(c.req.query("errorTo"));
  const { authorizationUrl, state, nonce, codeVerifier } = await buildAuthorizationRequest(
    getExternalOrigin(c)
  );

  setCookie(c, "oidc_state", state, oidcCookieOptions());
  setCookie(c, "oidc_nonce", nonce, oidcCookieOptions());
  setCookie(c, "oidc_verifier", codeVerifier, oidcCookieOptions());
  if (returnTo) {
    setCookie(c, "oidc_return_to", returnTo, oidcCookieOptions());
  }
  if (errorTo) {
    setCookie(c, "oidc_error_to", errorTo, oidcCookieOptions());
  }

  return c.redirect(authorizationUrl.toString());
});

app.get("/.well-known/jwks.json", async (c) => {
  return c.json(await getJwks());
});

/** The ADFS callback — this service's root literally *is* the registered,
 * fixed redirect_uri, so no forwarding hack is needed here. */
app.get("/", async (c) => {
  const url = new URL(c.req.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const origin = getExternalOrigin(c);

  if (!code || !state) {
    // Not an ADFS callback, so an old bookmark of bookingtools' former start
    // page.
    return c.redirect(`${origin}${LEGACY_TARGET_PREFIX}/`, 301);
  }

  const cookieState = getCookie(c, "oidc_state");
  const cookieNonce = getCookie(c, "oidc_nonce");
  const cookieVerifier = getCookie(c, "oidc_verifier");
  const returnTo = safeReturnTo(getCookie(c, "oidc_return_to"));
  const errorTo = safeReturnTo(getCookie(c, "oidc_error_to"));

  if (!cookieState || !cookieNonce || !cookieVerifier) {
    clearOidcCookies(c);
    return c.redirect(`${origin}${errorRedirectPath(errorTo, "oidc_state")}`);
  }

  try {
    const { claims, accessToken } = await exchangeCodeForClaims(url, origin, {
      state: cookieState,
      nonce: cookieNonce,
      codeVerifier: cookieVerifier,
    });

    const isGroupAdmin = isAdminGroupConfigured() ? await checkIsGroupAdmin(accessToken) : false;

    const identityToken = await signIdentityToken(
      { sub: claims.sub, email: claims.email, name: claims.name, isGroupAdmin },
      origin
    );

    clearOidcCookies(c);
    setCookie(c, IDENTITY_COOKIE_NAME, identityToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      domain: COOKIE_DOMAIN,
      maxAge: IDENTITY_COOKIE_MAX_AGE,
    });

    return c.redirect(`${origin}${returnTo ?? DEFAULT_RETURN_TO}`);
  } catch (error) {
    console.error("KTH OIDC login failed:", error);
    clearOidcCookies(c);
    return c.redirect(`${origin}${errorRedirectPath(errorTo, "oidc_failed")}`);
  }
});

const ERROR_MESSAGES: Record<string, { sv: string; en: string }> = {
  oidc_state: {
    sv: "Inloggningen tog för lång tid eller avbröts. Försök igen.",
    en: "The login took too long or was interrupted. Please try again.",
  },
  oidc_failed: {
    sv: "Inloggningen via KTH misslyckades. Försök igen om en stund.",
    en: "Logging in with KTH failed. Please try again in a moment.",
  },
};

/** The default error page, for apps that don't pass their own errorTo. Only
 * known error codes are shown - the query is never echoed into the page. */
app.get("/error", (c) => {
  const message = ERROR_MESSAGES[c.req.query("error") ?? ""] ?? ERROR_MESSAGES.oidc_failed;
  return c.html(`<!doctype html>
<html lang="sv">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Inloggningen misslyckades</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 32rem; margin: 4rem auto; padding: 0 1rem; color: #212121; }
  a { color: #1954a6; }
</style>
</head>
<body>
<h1>Inloggningen misslyckades</h1>
<p>${message.sv}</p>
<p lang="en">${message.en}</p>
<p><a href="/mrbs/login">Försök igen / Try again</a></p>
</body>
</html>`);
});

/** Safety net for old bookmarks/QR codes pointing at bookingtools' former
 * /mrbs/* paths (back when bookingtools itself owned this prefix). Swaps the
 * prefix and keeps the rest of the path + query, so /mrbs/rooms/12?date=...
 * lands on /bookingtools/rooms/12?date=..., whose legacy shim then forwards
 * it to the right schedule. */
app.get("/*", (c) => {
  const origin = getExternalOrigin(c);
  const url = new URL(c.req.url);
  const rest = url.pathname.replace(/^\/mrbs/, "");
  return c.redirect(`${origin}${LEGACY_TARGET_PREFIX}${rest}${url.search}`, 301);
});

const port = Number(process.env.PORT ?? 3000);
serve({ fetch: app.fetch, port }, (info) => {
  console.log(`librarytools-auth listening on :${info.port}`);
});
