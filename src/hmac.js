/**
 * HMAC signing and verification for the Agent Games protocol.
 *
 * The signature covers the RAW request body bytes, computed before JSON.parse.
 * Parsing first and re-serialising later would let a trailing whitespace change,
 * a duplicate key, or a different number formatting slip past the check.
 */
import { createHmac, timingSafeEqual } from "node:crypto";

export const SIGNATURE_HEADER = "x-agent-games-signature";

/** Compute the hex HMAC-SHA256 of a raw body buffer. */
export function sign(rawBody, secret) {
  if (!secret) throw new Error("HMAC secret missing");
  const buf = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody, "utf8");
  return createHmac("sha256", secret).update(buf).digest("hex");
}

/**
 * Compare a received signature against the expected one in constant time.
 *
 * Accepts an optional `sha256=` prefix and any hex case, because the platform's
 * exact encoding is not part of the published contract and a case mismatch
 * would otherwise fail preflight.
 */
export function verify(rawBody, headerValue, secret) {
  if (!headerValue || !secret) return false;
  const got = String(headerValue).trim().replace(/^sha256=/i, "").toLowerCase();
  const want = sign(rawBody, secret);
  if (got.length !== want.length) return false;
  try {
    return timingSafeEqual(Buffer.from(got, "hex"), Buffer.from(want, "hex"));
  } catch {
    return false;
  }
}
