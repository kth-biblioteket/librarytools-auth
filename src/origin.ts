import type { Context } from "hono";

/** Mirrors bookingtools' src/lib/request-origin.ts: this service sits behind
 * Traefik too, so the external host/proto must be read from the forwarded
 * headers rather than the local bind address. */
export function getExternalOrigin(c: Context): string {
  const forwardedProto = c.req.header("x-forwarded-proto");
  const forwardedHost = c.req.header("x-forwarded-host");
  const url = new URL(c.req.url);
  const proto = forwardedProto ?? url.protocol.replace(":", "");
  const host = forwardedHost ?? c.req.header("host") ?? url.host;
  return `${proto}://${host}`;
}
