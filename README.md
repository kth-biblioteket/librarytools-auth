# librarytools-auth

The thin, rarely-deployed KTH ADFS login broker for the "Librarytools" family
of KTH Library apps on `apps.lib.kth.se`. Owns the one fixed path the reused
Entra app registration is allowed to redirect to — `https://apps.lib.kth.se/mrbs`
(and the `ref` equivalent) — and nothing else.

## What it does

1. `GET /mrbs/login?returnTo=<path>` — starts the ADFS OIDC (Authorization
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
