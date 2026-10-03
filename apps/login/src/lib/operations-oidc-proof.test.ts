import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { verifyOperationsOidcProof } from "./operations-oidc-proof";

const issuer = "https://auth.paypm.test",
  clientId = "operations@paypm",
  nonce = Buffer.alloc(32, 11).toString("base64url"),
  accessToken = "synthetic-current-opaque-access",
  key = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...key.publicKey.export({ format: "jwk" }), kid: "fixture-rsa", use: "sig", alg: "RS256" };
let claims: any, introspection: any, keys: any[], fetcher: any;
function jwt(body = claims, header: any = { alg: "RS256", kid: "fixture-rsa", typ: "JWT" }) {
  const encoded = [header, body].map((value) => Buffer.from(JSON.stringify(value)).toString("base64url")).join(".");
  return `${encoded}.${sign("RSA-SHA256", Buffer.from(encoded), key.privateKey).toString("base64url")}`;
}
const input = () => ({ idToken: jwt(), accessToken, nonce, clientId });
beforeEach(() => {
  vi.stubEnv("PAYPM_OPERATIONS_INTROSPECTION_CLIENT_ID", "ops-resource@paypm");
  vi.stubEnv("PAYPM_OPERATIONS_INTROSPECTION_CLIENT_SECRET", Buffer.alloc(32, 12).toString("base64url"));
  const now = Math.floor(Date.now() / 1000);
  claims = {
    iss: issuer,
    sub: "700",
    aud: [clientId],
    azp: clientId,
    sid: "900",
    iat: now,
    exp: now + 300,
    auth_time: now - 2,
    nonce,
    at_hash: createHash("sha256").update(accessToken).digest().subarray(0, 16).toString("base64url"),
  };
  introspection = {
    active: true,
    iss: issuer,
    sub: "700",
    client_id: clientId,
    token_type: "Bearer",
    aud: [clientId],
    exp: now + 300,
    iat: now,
    nbf: now,
    jti: "v2_oidc-aggregate:separate-access-id",
  };
  keys = [jwk];
  fetcher = vi.fn(
    async (url: URL) => new Response(JSON.stringify(url.pathname.endsWith("keys") ? { keys } : introspection)),
  );
  vi.stubGlobal("fetch", fetcher);
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});
describe("signed pinned ZITADEL OIDC Session API provenance", () => {
  it("derives base from the real signed ID sid and preserves a distinct token jti", async () => {
    const raw = input(),
      proof = await verifyOperationsOidcProof(raw, issuer);
    expect(proof).toEqual({
      issuer,
      providerSubject: "700",
      baseSessionId: "900",
      clientId,
      tokenId: introspection.jti,
      idTokenHash: createHash("sha256").update(raw.idToken).digest("hex"),
      accessTokenHash: createHash("sha256").update(accessToken).digest("hex"),
      nonceHash: createHash("sha256").update(nonce).digest("hex"),
    });
    const calls = fetcher.mock.calls;
    expect(calls.map((c: any) => c[0].href)).toEqual([`${issuer}/oauth/v2/keys`, `${issuer}/oauth/v2/introspect`]);
    expect(calls[1][1].body.get("token")).toBe(accessToken);
    expect(calls[1][1].redirect).toBe("error");
    expect(calls[1][1].cache).toBe("no-store");
  });
  it.each([
    "signature",
    "algorithm",
    "kid",
    "duplicate-kid",
    "remote-jwk",
    "issuer",
    "audience",
    "azp",
    "nonce",
    "sid-jti",
    "missing-sid",
    "subject",
    "expired",
    "future-iat",
    "future-nbf",
    "old-auth",
    "long-life",
    "wrong-access-hash",
    "actor",
    "reused-secret",
  ])("rejects %s before accepting current admission", async (kind) => {
    let raw = input();
    if (kind === "algorithm") raw.idToken = jwt(claims, { alg: "HS256", kid: "fixture-rsa" });
    if (kind === "signature") raw.idToken = `${raw.idToken.slice(0, -10)}${"A".repeat(10)}`;
    if (kind === "kid") keys = [{ ...jwk, kid: "other" }];
    if (kind === "duplicate-kid") keys = [jwk, jwk];
    if (kind === "remote-jwk")
      raw.idToken = jwt(claims, { alg: "RS256", kid: "fixture-rsa", jku: "https://evil.test/keys" });
    if (kind === "issuer") claims.iss = "https://other.test";
    if (kind === "audience") claims.aud = ["other"];
    if (kind === "azp") claims.azp = "other";
    if (kind === "nonce") claims.nonce = Buffer.alloc(32, 13).toString("base64url");
    if (kind === "sid-jti") claims.sid = introspection.jti;
    if (kind === "missing-sid") delete claims.sid;
    if (kind === "subject") claims.sub = "machine@other";
    if (kind === "expired") claims.exp = claims.iat - 1;
    if (kind === "future-iat") claims.iat += 90;
    if (kind === "future-nbf") claims.nbf = claims.iat + 90;
    if (kind === "old-auth") claims.auth_time -= 28800;
    if (kind === "long-life") claims.exp = claims.iat + 30000;
    if (kind === "wrong-access-hash") raw.accessToken = "different-access";
    if (kind === "actor") claims.act = { sub: "admin" };
    if (kind === "reused-secret")
      vi.stubEnv("PAYPM_OPERATIONS_ADMISSION_READER_TOKEN", process.env.PAYPM_OPERATIONS_INTROSPECTION_CLIENT_SECRET!);
    if (!["signature", "algorithm", "remote-jwk"].includes(kind)) raw.idToken = jwt();
    await expect(verifyOperationsOidcProof(raw, issuer)).rejects.toThrow();
  });
  it.each([
    "revoked",
    "wrong-client",
    "wrong-person",
    "wrong-aud",
    "wrong-issuer",
    "refresh",
    "expired",
    "long-life",
    "missing-jti",
    "actor",
    "outage",
  ])("rejects native introspection %s", async (kind) => {
    if (kind === "revoked") introspection.active = false;
    if (kind === "wrong-client") introspection.client_id = "other";
    if (kind === "wrong-person") introspection.sub = "701";
    if (kind === "wrong-aud") introspection.aud = ["other"];
    if (kind === "wrong-issuer") introspection.iss = "https://other.test";
    if (kind === "refresh") introspection.token_type = "refresh_token";
    if (kind === "expired") introspection.exp -= 600;
    if (kind === "long-life") introspection.exp = introspection.iat + 301;
    if (kind === "missing-jti") delete introspection.jti;
    if (kind === "actor") introspection.act = { sub: "admin" };
    if (kind === "outage") fetcher.mockRejectedValue(new Error("provider unavailable"));
    await expect(verifyOperationsOidcProof(input(), issuer)).rejects.toThrow();
  });
});
