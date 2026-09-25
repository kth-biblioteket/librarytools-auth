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
const DEFAULT_RETURN_TO = process.env.DEFAULT_RETURN_TO || "/";
const LOGIN_ERROR_PATH = process.env.LOGIN_ERROR_PATH || "/mrbs/error";
// Apps on other hosts (e.g. https://spacefinder.lib.kth.se) allowed as an
// absolute returnTo/errorTo. An explicit list, not a domain, since not every
// host under lib.kth.se is ours. Apps on this service's own host never need
// to be listed - they use relative paths.
const ALLOWED_APP_ORIGINS = new Set(
  (process.env.ALLOWED_APP_ORIGINS ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => new URL(entry).origin)
);

// strict: false so /mrbs/ is the callback too, not the catch-all - a
// trailing slash on the way back from ADFS must not silently drop the login.
const app = new Hono({ strict: false }).basePath("/mrbs");

function oidcCookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax" as const,
    path: "/",
    maxAge: OIDC_COOKIE_MAX_AGE,
  };
}

/** Where a returnTo/errorTo points: a path on this service's own host, or
 * an absolute URL on one of ALLOWED_APP_ORIGINS. */
type Target = { kind: "local"; path: string } | { kind: "remote"; url: URL };

/** Anything else is rejected: no protocol-relative "//host" (or "/\host",
 * which browsers read the same way) and no unlisted hosts. */
function parseTarget(value: string | undefined | null): Target | null {
  if (!value) return null;
  if (/^\/(?![\/\\])/.test(value)) return { kind: "local", path: value };
  try {
    const url = new URL(value);
    if (ALLOWED_APP_ORIGINS.has(url.origin) && !url.username && !url.password) {
      return { kind: "remote", url };
    }
  } catch {
    // Not a URL at all.
  }
  return null;
}

/** The fallbacks come from env, so a bad value fails at startup rather than
 * mid-login. */
function requireTarget(name: string, value: string): Target {
  const target = parseTarget(value);
  if (!target) {
    throw new Error(`${name}=${value} must be a /path or a URL on ALLOWED_APP_ORIGINS.`);
  }
  return target;
}

const DEFAULT_RETURN_TARGET = requireTarget("DEFAULT_RETURN_TO", DEFAULT_RETURN_TO);
const LOGIN_ERROR_TARGET = requireTarget("LOGIN_ERROR_PATH", LOGIN_ERROR_PATH);

function targetUrl(target: Target, origin: string): string {
  return target.kind === "local" ? `${origin}${target.path}` : target.url.href;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function clearOidcCookies(c: Parameters<typeof deleteCookie>[0]) {
  for (const name of ["oidc_state", "oidc_nonce", "oidc_verifier", "oidc_return_to", "oidc_error_to"]) {
    deleteCookie(c, name, { path: "/" });
  }
}

/** Appends ?error=<code> to the calling app's own error page (errorTo),
 * falling back to LOGIN_ERROR_PATH when the app didn't give one. */
function errorRedirectUrl(errorTo: Target | null, origin: string, error: "oidc_state" | "oidc_failed"): string {
  const url = new URL(targetUrl(errorTo ?? LOGIN_ERROR_TARGET, origin));
  url.searchParams.set("error", error);
  return url.href;
}

app.get("/login", async (c) => {
  const returnTo = c.req.query("returnTo");
  // Each app's own login/error page, so a failed round trip lands back in
  // the app that started it.
  const errorTo = c.req.query("errorTo");
  const { authorizationUrl, state, nonce, codeVerifier } = await buildAuthorizationRequest(
    getExternalOrigin(c)
  );

  setCookie(c, "oidc_state", state, oidcCookieOptions());
  setCookie(c, "oidc_nonce", nonce, oidcCookieOptions());
  setCookie(c, "oidc_verifier", codeVerifier, oidcCookieOptions());
  // Validated again on the way back, since cookies can't be trusted either.
  if (parseTarget(returnTo)) {
    setCookie(c, "oidc_return_to", returnTo!, oidcCookieOptions());
  }
  if (parseTarget(errorTo)) {
    setCookie(c, "oidc_error_to", errorTo!, oidcCookieOptions());
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
    // Not an ADFS callback (a direct visit or an old bookmark).
    return c.redirect(targetUrl(DEFAULT_RETURN_TARGET, origin));
  }

  const cookieState = getCookie(c, "oidc_state");
  const cookieNonce = getCookie(c, "oidc_nonce");
  const cookieVerifier = getCookie(c, "oidc_verifier");
  const returnTo = parseTarget(getCookie(c, "oidc_return_to")) ?? DEFAULT_RETURN_TARGET;
  const errorTo = parseTarget(getCookie(c, "oidc_error_to"));

  if (!cookieState || !cookieNonce || !cookieVerifier) {
    clearOidcCookies(c);
    return c.redirect(errorRedirectUrl(errorTo, origin, "oidc_state"));
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
      origin,
      returnTo.kind === "local" ? origin : returnTo.url.origin
    );

    clearOidcCookies(c);

    if (returnTo.kind === "remote") {
      // Another host: the cookie wouldn't reach it, and a wider cookie domain
      // would leak the token to every host under it. POST it straight to the
      // app instead, so only the audience ever sees it.
      c.header("Cache-Control", "no-store");
      c.header("Referrer-Policy", "no-referrer");
      return c.html(`<!doctype html>
<html lang="sv">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Loggar in…</title>
</head>
<body>
<form method="post" action="${escapeHtml(returnTo.url.href)}">
<input type="hidden" name="${IDENTITY_COOKIE_NAME}" value="${escapeHtml(identityToken)}">
<noscript><button type="submit">Fortsätt / Continue</button></noscript>
</form>
<script>document.forms[0].submit();</script>
</body>
</html>`);
    }

    setCookie(c, IDENTITY_COOKIE_NAME, identityToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      domain: COOKIE_DOMAIN,
      maxAge: IDENTITY_COOKIE_MAX_AGE,
    });

    return c.redirect(targetUrl(returnTo, origin));
  } catch (error) {
    console.error("KTH OIDC login failed:", error);
    clearOidcCookies(c);
    return c.redirect(errorRedirectUrl(errorTo, origin, "oidc_failed"));
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

/** Anything else under /mrbs (old bookmarks from before this service owned
 * the prefix, typos): nothing here belongs to any app, so just send the
 * browser to the neutral fallback. */
app.get("/*", (c) => c.redirect(targetUrl(DEFAULT_RETURN_TARGET, getExternalOrigin(c))));

const port = Number(process.env.PORT ?? 3000);
serve({ fetch: app.fetch, port }, (info) => {
  console.log(`librarytools-auth listening on :${info.port}`);
});
