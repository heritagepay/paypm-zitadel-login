import { createHash, createPublicKey, timingSafeEqual, verify } from "node:crypto";
import "server-only";

export type OperationsOidcProof = {
  issuer: string;
  providerSubject: string;
  baseSessionId: string;
  clientId: string;
  tokenId: string;
  idTokenHash: string;
  accessTokenHash: string;
  nonceHash: string;
};
const denied = () => new Error("Operations OIDC proof unavailable");
const hash = (value: string) => createHash("sha256").update(value).digest("hex");
function equal(a: string, b: string) {
  const x = Buffer.from(a),
    y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
function segment(value: string) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw denied();
  const result = Buffer.from(value, "base64url");
  if (result.toString("base64url") !== value) throw denied();
  return result;
}
const numeric = (value: unknown): value is number => Number.isSafeInteger(value) && Number(value) > 0;
const audiences = (value: unknown): string[] =>
  typeof value === "string" ? [value] : Array.isArray(value) && value.every((v) => typeof v === "string") ? value : [];
async function json(response: Response) {
  if (!response.ok) throw denied();
  const raw = await response.text();
  if (Buffer.byteLength(raw) > 131072) throw denied();
  return JSON.parse(raw);
}

/** Pinned ZITADEL v4.15.3 ID-token sid is the Session API ID, not access-token jti. */
export async function verifyOperationsOidcProof(
  input: {
    idToken: string;
    accessToken: string;
    nonce: string;
    clientId: string;
  },
  issuer: string,
): Promise<OperationsOidcProof> {
  const resourceClient = process.env.PAYPM_OPERATIONS_INTROSPECTION_CLIENT_ID,
    resourceSecret = process.env.PAYPM_OPERATIONS_INTROSPECTION_CLIENT_SECRET;
  if (
    !resourceClient ||
    !resourceSecret ||
    resourceSecret.length < 32 ||
    [
      process.env.PAYPM_OPERATIONS_ADMISSION_READER_TOKEN,
      process.env.PAYPM_WORKFORCE_ADMISSION_READER_TOKEN,
      process.env.PAYPM_WORKFORCE_IDENTITY_CLIENT_SECRET,
      process.env.PAYPM_WORKFORCE_FLOW_KEY_BASE64,
      process.env.PAYPM_WORKFORCE_STORE_KEY_BASE64,
    ].includes(resourceSecret)
  )
    throw denied();
  const origin = new URL(issuer);
  if (origin.protocol !== "https:" || origin.origin !== issuer) throw denied();
  const parts = input.idToken.split(".");
  if (
    parts.length !== 3 ||
    input.idToken.length > 16384 ||
    input.accessToken.length > 8192 ||
    input.accessToken.length === 0 ||
    !/^[A-Za-z0-9_-]{32,200}$/.test(input.nonce)
  )
    throw denied();
  const header = JSON.parse(segment(parts[0]).toString("utf8"));
  if (
    !header ||
    header.alg !== "RS256" ||
    (header.typ !== undefined && header.typ !== "JWT") ||
    typeof header.kid !== "string" ||
    !/^[A-Za-z0-9._:-]{1,200}$/.test(header.kid) ||
    header.jku !== undefined ||
    header.jwk !== undefined ||
    header.x5u !== undefined ||
    header.crit !== undefined
  )
    throw denied();
  const options = { cache: "no-store" as const, redirect: "error" as const, signal: AbortSignal.timeout(5000) };
  const jwks = await json(await fetch(new URL("/oauth/v2/keys", issuer), options));
  if (!Array.isArray(jwks.keys) || jwks.keys.length > 50) throw denied();
  const matching = jwks.keys.filter((key: Record<string, unknown>) => key?.kid === header.kid);
  if (matching.length !== 1) throw denied();
  const key = matching[0];
  if (
    key.kty !== "RSA" ||
    (key.use !== undefined && key.use !== "sig") ||
    (key.alg !== undefined && key.alg !== "RS256") ||
    typeof key.n !== "string" ||
    typeof key.e !== "string" ||
    segment(key.n).length < 256 ||
    (key.key_ops !== undefined && (!Array.isArray(key.key_ops) || key.key_ops.length !== 1 || key.key_ops[0] !== "verify"))
  )
    throw denied();
  if (
    !verify("RSA-SHA256", Buffer.from(`${parts[0]}.${parts[1]}`), createPublicKey({ key, format: "jwk" }), segment(parts[2]))
  )
    throw denied();
  const claims = JSON.parse(segment(parts[1]).toString("utf8"));
  const now = Math.floor(Date.now() / 1000),
    aud = audiences(claims.aud);
  const atHash = createHash("sha256").update(input.accessToken).digest().subarray(0, 16).toString("base64url");
  if (
    claims.iss !== issuer ||
    claims.azp !== input.clientId ||
    aud.length === 0 ||
    aud.length > 16 ||
    new Set(aud).size !== aud.length ||
    !aud.includes(input.clientId) ||
    typeof claims.sub !== "string" ||
    !/^[1-9]\d{0,39}$/.test(claims.sub) ||
    typeof claims.sid !== "string" ||
    !/^[1-9]\d{0,39}$/.test(claims.sid) ||
    !numeric(claims.iat) ||
    !numeric(claims.exp) ||
    !numeric(claims.auth_time) ||
    claims.iat > now + 30 ||
    claims.exp <= now ||
    claims.exp <= claims.iat ||
    claims.exp - claims.iat > 28830 ||
    claims.auth_time > claims.iat + 30 ||
    now - claims.auth_time > 28800 ||
    (claims.nbf !== undefined && (!numeric(claims.nbf) || claims.nbf > now + 30)) ||
    typeof claims.nonce !== "string" ||
    !equal(claims.nonce, input.nonce) ||
    typeof claims.at_hash !== "string" ||
    !equal(claims.at_hash, atHash) ||
    claims.act !== undefined
  )
    throw denied();
  const introspected = await json(
    await fetch(new URL("/oauth/v2/introspect", issuer), {
      ...options,
      signal: AbortSignal.timeout(5000),
      method: "POST",
      headers: {
        authorization: `Basic ${Buffer.from(`${encodeURIComponent(resourceClient)}:${encodeURIComponent(resourceSecret)}`).toString("base64")}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ token: input.accessToken, token_type_hint: "access_token" }),
    }),
  );
  if (
    introspected.active !== true ||
    introspected.iss !== issuer ||
    introspected.sub !== claims.sub ||
    introspected.client_id !== input.clientId ||
    introspected.token_type !== "Bearer" ||
    !audiences(introspected.aud).includes(input.clientId) ||
    !numeric(introspected.exp) ||
    introspected.exp <= now ||
    !numeric(introspected.iat) ||
    introspected.iat > now + 30 ||
    introspected.exp <= introspected.iat ||
    introspected.exp - introspected.iat > 300 ||
    !numeric(introspected.nbf) ||
    introspected.nbf > now + 30 ||
    introspected.act !== undefined ||
    typeof introspected.jti !== "string" ||
    introspected.jti.length === 0 ||
    introspected.jti.length > 500
  )
    throw denied();
  return {
    issuer,
    providerSubject: claims.sub,
    baseSessionId: claims.sid,
    clientId: input.clientId,
    tokenId: introspected.jti,
    idTokenHash: hash(input.idToken),
    accessTokenHash: hash(input.accessToken),
    nonceHash: hash(input.nonce),
  };
}
