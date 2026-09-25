# librarytools-auth

The thin, rarely-deployed KTH ADFS login broker for the "Librarytools" family
of KTH Library apps on `apps.lib.kth.se`.

## What it does

1. `GET /mrbs/login?returnTo=<path or URL>&errorTo=<path or URL>` — starts the ADFS OIDC (Authorization
   Code + PKCE) dance, redirects to Entra ID.
2. `GET /mrbs` — the ADFS callback. Exchanges the code for the user's
   claims, optionally checks KTH-group admin membership via Microsoft Graph,
   signs a short-lived (60s) identity JWT with those claims and hands it to
   the app at `returnTo`: as a `kth_identity` cookie for apps on this host,
   or POSTed to `returnTo` for apps on other hosts.
3. `GET /mrbs/.well-known/jwks.json` — the public key consuming apps
   (bookingtools today, others later) use to verify that JWT locally, no
   network call or shared secret needed per request.

It never touches any app's database, never provisions users, and never
issues app-level sessions — each consuming app does that itself on seeing a
valid identity JWT (see bookingtools' `proxy.ts`).

## Using it from an app

Any app on the same host, or on another host listed in
`ALLOWED_APP_ORIGINS`, can use it, whatever it's written in (Node, PHP,
...). The contract is just a signed JWT, so there's no library to depend on
beyond a JWT one that supports EdDSA.

### 1. Send the browser to the login

```
https://apps.lib.kth.se/mrbs/login?returnTo=<path or URL>&errorTo=<path or URL>
```

- `returnTo`: where to come back to after a successful login, e.g.
  `/minapp/sida?x=1` (URL-encoded). Defaults to `DEFAULT_RETURN_TO` (`/`).
- `errorTo`: the app's own login/error page. On failure the browser lands on
  `errorTo?error=oidc_state` (the round trip took too long / cookies were
  lost) or `errorTo?error=oidc_failed` (ADFS or the token exchange failed).
  Defaults to `LOGIN_ERROR_PATH`, this service's own simple error page
  `/mrbs/error`. Pass your own so the user stays in your app.

Apps on `apps.lib.kth.se` pass relative paths (`/...`, not `//host`). Apps
on another host (e.g. `spacefinder.lib.kth.se`) pass full URLs, and their
origin must be listed in this service's `ALLOWED_APP_ORIGINS` - one entry
per app and environment, since not every host under `lib.kth.se` is ours.
Anything else is ignored and the fallback is used.

How the token then reaches the app depends on which of the two it is:
section 2 for apps on this host, section 3 for apps on other hosts.

### 2. Apps on `apps.lib.kth.se`: consume the `kth_identity` cookie

On success the browser is redirected to `returnTo` with a `kth_identity`
cookie (`Domain=apps.lib.kth.se`, `Path=/`, HttpOnly, 60 s). It's HttpOnly,
so it has to be handled **server-side**: for a React/plain-JS frontend that's
the backend serving it or its API, not browser code.

When a request carries it, the app should:

1. **Delete it right away**, whatever happens next, with the same `Domain`
   and `Path=/`. It's a single-use handoff, not a session.
2. **Verify it** against `https://<host>/mrbs/.well-known/jwks.json`, with
   the algorithm pinned to `EdDSA`, `exp` checked (the libraries do this) and
   `iss` checked to be `https://<host>`. Cache the JWKS, don't fetch it on
   every request. `aud` is `https://apps.lib.kth.se` here, shared by every
   app on the host, so checking it is optional.
3. **Read the claims**: `sub` (stable ADFS subject, the key to store users
   by), `email`, `name`, `isGroupAdmin` (member of `OIDC_ADMIN_GROUP_ID`, or
   always `false` when that isn't set).
4. **Start its own session** (create the user on first login if it wants
   to) and redirect to the same URL without the cookie, so a reload doesn't
   hit the handoff again.

If verification fails, treat the user as not logged in. Don't show an error;
the token has simply expired or been tampered with.

#### Node (`jose`)

```ts
import { createRemoteJWKSet, jwtVerify } from "jose";

const HOST = "https://apps.lib.kth.se";
const JWKS = createRemoteJWKSet(new URL(`${HOST}/mrbs/.well-known/jwks.json`)); // caches itself

export async function verifyIdentity(token: string) {
  const { payload } = await jwtVerify(token, JWKS, { issuer: HOST, algorithms: ["EdDSA"] });
  return payload as { sub: string; email: string; name: string; isGroupAdmin: boolean };
}
```

#### PHP (`firebase/php-jwt` 6.x with Ed25519/OKP JWK support, needs `ext-sodium`)

```php
use Firebase\JWT\JWT;
use Firebase\JWT\JWK;

const HOST = 'https://apps.lib.kth.se';

$token = $_COOKIE['kth_identity'] ?? null;
if ($token !== null) {
    setcookie('kth_identity', '', [
        'expires' => 1, 'path' => '/', 'domain' => 'apps.lib.kth.se',
        'secure' => true, 'httponly' => true, 'samesite' => 'Lax',
    ]);
    try {
        // Cache this (APCu, a file, ...) rather than fetching on every login.
        $jwks = json_decode(file_get_contents(HOST . '/mrbs/.well-known/jwks.json'), true);
        $claims = JWT::decode($token, JWK::parseKeySet($jwks, 'EdDSA'));
        if ($claims->iss !== HOST) {
            throw new UnexpectedValueException('wrong issuer');
        }
        session_regenerate_id(true);
        $_SESSION['user'] = [
            'sub' => $claims->sub, 'email' => $claims->email,
            'name' => $claims->name, 'isGroupAdmin' => $claims->isGroupAdmin,
        ];
        header('Location: ' . $_SERVER['REQUEST_URI']);
        exit;
    } catch (Throwable $e) {
        // Expired or invalid: just not logged in.
    }
}
```

### 3. Apps on other hosts: receive the POST

A cookie on `apps.lib.kth.se` never reaches another host, and a cookie on
all of `lib.kth.se` would leak the token to every host under it. So when
`returnTo` is a full URL, the service instead answers with a small page that
immediately **POSTs** the token to that URL as the form field
`kth_identity` (`application/x-www-form-urlencoded`). No cookie is set, and
the token never appears in a URL.

So `returnTo` has to be a server-side endpoint that accepts that POST, e.g.
`https://spacefinder.lib.kth.se/auth/kth`. It should:

1. **Check its own state first** (login CSRF protection): before sending the
   browser to `/mrbs/login`, set a random value in a cookie of your own and
   put the same value in `returnTo`, e.g. `.../auth/kth?state=<value>`. On
   the POST, reject it unless they match, so nobody can log a user into
   *their* account by posting their own token.
2. **Verify the token** as in section 2 (`EdDSA`, `exp`,
   `iss` = `https://apps.lib.kth.se`), and **also `aud`**, which must be the
   app's own origin (e.g. `https://spacefinder.lib.kth.se`). This is
   required here: it's what stops a token handed to one app from being used
   against another.
3. **Start its own session** and redirect (303) to wherever the user was
   going.

`errorTo` can be a full URL on the same app too; errors are a plain redirect
with `?error=...`, no token involved.

In code that's the same as section 2 with the token read from the POST body
instead of the cookie and the audience added:

```ts
await jwtVerify(token, JWKS, {
  issuer: "https://apps.lib.kth.se",
  audience: "https://spacefinder.lib.kth.se",
  algorithms: ["EdDSA"],
});
```

```php
$claims = JWT::decode($_POST['kth_identity'], JWK::parseKeySet($jwks, 'EdDSA'));
if ($claims->iss !== 'https://apps.lib.kth.se' || $claims->aud !== 'https://spacefinder.lib.kth.se') {
    throw new UnexpectedValueException('wrong issuer or audience');
}
```

(`php-jwt` doesn't check `aud` by itself, hence the explicit comparison.)
On ref, the issuer and JWKS are on `apps-ref.lib.kth.se`, and the app's ref
origin has to be in the ref instance's `ALLOWED_APP_ORIGINS`.

`OIDC_*` are only required to actually exercise `/login`/the callback — the
server starts and `/mrbs/.well-known/jwks.json` works without them.

## Deploy

CI (`.github/workflows/deploy_ref.yml`/
`deploy_main.yml`) builds and pushes a Docker image to
`ghcr.io/kth-biblioteket/librarytools-auth`, then hits the same deploy
webhook. `docker-compose.yml` has no database service — this app is
stateless.
