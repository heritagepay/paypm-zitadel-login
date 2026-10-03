import "server-only";
function url(value: string | undefined) {
  if (!value) throw new Error("Identity service unavailable");
  const parsed = new URL(value);
  if (
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    (parsed.protocol !== "https:" &&
      !(
        process.env.NODE_ENV !== "production" &&
        parsed.protocol === "http:" &&
        ["localhost", "127.0.0.1"].includes(parsed.hostname)
      ))
  )
    throw new Error("Identity service unavailable");
  return parsed;
}
/** Dedicated machine client; no human browser token or provider session token is forwarded. */
export async function workforceIdentityRequest(path: string, body: unknown): Promise<unknown> {
  if (!/^internal\/v1\/workforce-action-proofs\/(requests|requests\/[0-9a-f-]{36}\/complete)$/.test(path))
    throw new Error("Unregistered Identity contract");
  const base = url(process.env.PAYPM_WORKFORCE_IDENTITY_URL),
    tokenUrl = url(process.env.PAYPM_WORKFORCE_IDENTITY_TOKEN_URL);
  const clientId = process.env.PAYPM_WORKFORCE_IDENTITY_CLIENT_ID,
    secret = process.env.PAYPM_WORKFORCE_IDENTITY_CLIENT_SECRET,
    scopes = process.env.PAYPM_WORKFORCE_IDENTITY_SCOPES;
  if (!clientId || !secret || !scopes) throw new Error("Identity service unavailable");
  const tokenResult = await fetch(tokenUrl, {
    method: "POST",
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(5000),
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      client_id: clientId,
      client_secret: secret,
      scope: scopes,
    }),
  });
  if (!tokenResult.ok) throw new Error("Identity service unavailable");
  const token: unknown = await tokenResult.json();
  if (
    !token ||
    typeof token !== "object" ||
    !("access_token" in token) ||
    typeof token.access_token !== "string" ||
    !token.access_token
  )
    throw new Error("Identity service unavailable");
  const result = await fetch(new URL(path, base.href.endsWith("/") ? base : `${base.href}/`), {
    method: "POST",
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(5000),
    headers: { authorization: `Bearer ${token.access_token}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!result.ok) throw new Error("Workforce action proof denied");
  return result.json();
}
