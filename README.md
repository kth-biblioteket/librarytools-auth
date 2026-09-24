# librarytools-auth

The thin, rarely-deployed KTH ADFS login broker for the "Librarytools" family
of KTH Library apps on `apps.lib.kth.se`. Owns the one fixed path the reused
Entra app registration is allowed to redirect to — `https://apps.lib.kth.se/mrbs`
(and the `ref` equivalent) — and nothing else.

## What it does

1. `GET /mrbs/login?returnTo=<path>&errorTo=<path>` — starts the ADFS OIDC (Authorization
   Code + PKCE) dance, redirects to Entra ID.
2. `GET /mrbs` — the ADFS callback. Exchanges the code for the user's
   claims, optionally checks KTH-group admin membership via Microsoft Graph,
   signs a short-lived (60s) identity JWT with those claims, sets it as a
   `kth_identity` cookie on the shared domain, and redirects the browser to
   `returnTo`.
3. `GET /mrbs/.well-known/jwks.json` — the public key consuming apps
   (bookingtools today, others later) use to verify that JWT locally, no
   network call or shared secret needed per request.

It never touches any app's database, never provisions users, and never
issues app-level sessions — each consuming app does that itself on seeing a
valid identity JWT (see bookingtools' `proxy.ts`).

See `/Users/tholind/.claude/plans/vad-vi-beh-ver-r-zazzy-wombat.md` in the
bookingtools repo for the full design rationale (why this is a separate
repo, the JWT contract, rollout/cutover plan).

## Using it from an app

Any app on the same host can use it, whatever it's written in (Node, PHP,
...). The contract is just a signed JWT in a cookie, so there's no library to
depend on beyond a JWT one that supports EdDSA.

### 1. Send the browser to the login

```
https://apps.lib.kth.se/mrbs/login?returnTo=<path>&errorTo=<path>
```

- `returnTo`: where to come back to after a successful login, e.g.
  `/minapp/sida?x=1` (URL-encoded). Defaults to `DEFAULT_RETURN_TO`.
- `errorTo`: the app's own login/error page. On failure the browser lands on
  `errorTo?error=oidc_state` (the round trip took too long / cookies were
  lost) or `errorTo?error=oidc_failed` (ADFS or the token exchange failed).
  Defaults to `LOGIN_ERROR_PATH`.

Both must be relative paths on the same host (`/...`, not `//host` or a full
URL); anything else is ignored.

### 2. Consume the `kth_identity` cookie

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
   every request.
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

bookingtools' `src/proxy.ts` is a complete example (verify, provision,
session, redirect).

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

Use `apps-ref.lib.kth.se` for both host and cookie domain on ref.

## Local development

```bash
npm install
openssl genpkey -algorithm ed25519 -out /tmp/key.pem
AUTH_SIGNING_PRIVATE_KEY="$(cat /tmp/key.pem)" \
OIDC_ISSUER=... OIDC_CLIENT_ID=... OIDC_CLIENT_SECRET=... \
PORT=4111 npm run dev
```

`OIDC_*` are only required to actually exercise `/login`/the callback — the
server starts and `/mrbs/.well-known/jwks.json` works without them.

## Deploy

Same pattern as bookingtools: CI (`.github/workflows/deploy_ref.yml`/
`deploy_main.yml`) builds and pushes a Docker image to
`ghcr.io/kth-biblioteket/librarytools-auth`, then hits the same deploy
webhook. `docker-compose.yml` has no database service — this app is
stateless.
