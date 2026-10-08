// @vitest-environment node
import { randomUUID } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  enrollmentIdentityRequest,
  parseEnrollmentCompletion,
  parseEnrollmentProjection,
} from "./workforce-enrollment-identity-client";
const id = randomUUID(),
  challenge = randomUUID(),
  runtime = { sourceRevision: "a".repeat(40), imageDigest: "b".repeat(64), configurationSha256: "c".repeat(64) };
const projection = () => ({
  enrollmentId: id,
  personId: randomUUID(),
  policyId: randomUUID(),
  issuer: "https://auth.paypm.test",
  organizationId: "300",
  clientId: "staff-client",
  providerSubject: "700",
  email: "staff@example.test",
  emailVerified: false,
  ...runtime,
  expiresAt: new Date(Date.now() + 120000).toISOString(),
  state: "qualified_enrollment",
});
const completion = () => ({
  ceremonySha256: "d".repeat(64),
  clientId: "staff-client",
  contactId: randomUUID(),
  enrollmentId: id,
  evidenceId: challenge,
  issuer: "https://auth.paypm.test",
  organizationId: "300",
  ownerDecisionSha256: "e".repeat(64),
  personId: randomUUID(),
  policyId: randomUUID(),
  profileClass: "workforce",
  providerSessionId: "800",
  reviewedCollisionSha256: "f".repeat(64),
  state: "completed",
  subject: "700",
  verifiedAt: new Date(Date.now() - 1000).toISOString(),
});
beforeEach(() => {
  for (const [key, value] of Object.entries({
    PAYPM_WORKFORCE_ISSUER: "https://auth.paypm.test",
    PAYPM_WORKFORCE_ORGANIZATION_ID: "300",
    PAYPM_WORKFORCE_OIDC_CLIENT_IDS: "staff-client",
    PAYPM_WORKFORCE_ENROLLMENT_RUNTIME_JSON: JSON.stringify(runtime),
    PAYPM_WORKFORCE_IDENTITY_URL: "https://identity.paypm.test/api",
    PAYPM_WORKFORCE_IDENTITY_TOKEN_URL: "https://auth.paypm.test/oauth/v2/token",
    PAYPM_WORKFORCE_ENROLLMENT_IDENTITY_CLIENT_ID: "enrollment-machine",
    PAYPM_WORKFORCE_ENROLLMENT_IDENTITY_CLIENT_SECRET: "separate-synthetic-enrollment-secret",
    PAYPM_WORKFORCE_ENROLLMENT_IDENTITY_SCOPES: "openid urn:zitadel:iam:org:project:id:1:aud",
  }))
    vi.stubEnv(key, value);
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});
describe("closed purpose-specific Identity authority", () => {
  it("uses only configured token and owning current route with one signal and no-store", async () => {
    const p = projection(),
      fetch = vi
        .fn()
        .mockResolvedValueOnce(Response.json({ access_token: "private-token", token_type: "Bearer" }))
        .mockResolvedValueOnce(Response.json(p));
    vi.stubGlobal("fetch", fetch);
    expect(await enrollmentIdentityRequest("current", id)).toEqual(p);
    expect(String(fetch.mock.calls[0][0])).toBe("https://auth.paypm.test/oauth/v2/token");
    expect(String(fetch.mock.calls[1][0])).toBe(
      `https://identity.paypm.test/api/internal/v1/reviewed-workforce-enrollments/${id}/current`,
    );
    const a = fetch.mock.calls[0][1],
      b = fetch.mock.calls[1][1];
    expect(a.signal).toBe(b.signal);
    expect(b).toMatchObject({ method: "POST", cache: "no-store", redirect: "error", body: "{}" });
    expect(JSON.stringify(p)).not.toContain("private-token");
  });
  it.each(["off", "shared-client", "shared-secret", "body-authority", "bad-id", "bad-base"])(
    "denies %s before fetching",
    async (kind) => {
      const fetch = vi.fn();
      vi.stubGlobal("fetch", fetch);
      let body: any = {},
        op: string = id;
      if (kind === "off") vi.stubEnv("PAYPM_WORKFORCE_ENROLLMENT_RUNTIME_JSON", "");
      if (kind === "shared-client") vi.stubEnv("PAYPM_WORKFORCE_IDENTITY_CLIENT_ID", "enrollment-machine");
      if (kind === "shared-secret")
        vi.stubEnv("PAYPM_IDENTITY_ACTION_IDENTITY_CLIENT_SECRET", "separate-synthetic-enrollment-secret");
      if (kind === "body-authority") body = { personId: randomUUID() };
      if (kind === "bad-id") op = "../complete";
      if (kind === "bad-base") vi.stubEnv("PAYPM_WORKFORCE_IDENTITY_URL", "https://evil@identity.paypm.test/api");
      await expect(enrollmentIdentityRequest("current", op, body)).rejects.toThrow();
      expect(fetch).not.toHaveBeenCalled();
    },
  );
  it.each(["person", "subject", "source", "email", "verified", "expiry", "extra", "client"])(
    "rejects malformed/changed projection %s",
    (kind) => {
      const p: any = projection();
      if (kind === "person") p.personId = p.email;
      if (kind === "subject") p.providerSubject = true;
      if (kind === "source") p.sourceRevision = "d".repeat(40);
      if (kind === "email") p.email = "Staff@example.test";
      if (kind === "verified") p.emailVerified = "true";
      if (kind === "expiry") p.expiresAt = new Date(Date.now() - 1).toISOString();
      if (kind === "extra") p.roles = ["admin"];
      if (kind === "client") p.clientId = "other";
      expect(() => parseEnrollmentProjection(p, id)).toThrow();
    },
  );
  it("rejects oversize stream and bad token, never forwards a malformed authority response", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(Response.json({ access_token: "secret", token_type: "Bearer" }))
      .mockResolvedValueOnce(new Response("x".repeat(16385)));
    vi.stubGlobal("fetch", fetch);
    await expect(enrollmentIdentityRequest("current", id)).rejects.toThrow("cap");
    fetch.mockReset().mockResolvedValueOnce(Response.json({ access_token: "secret", token_type: "refresh" }));
    await expect(enrollmentIdentityRequest("current", id)).rejects.toThrow("token");
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it("accepts only the exact completed original, no granted permissions", () => {
    const p = completion();
    expect(parseEnrollmentCompletion(p, id, { challengeId: challenge, sessionId: "800" })).toEqual(p);
    expect(() =>
      parseEnrollmentCompletion({ ...p, evidenceId: randomUUID() }, id, { challengeId: challenge, sessionId: "800" }),
    ).toThrow();
    expect(() =>
      parseEnrollmentCompletion({ ...p, roles: ["admin"] }, id, { challengeId: challenge, sessionId: "800" }),
    ).toThrow();
    expect(() =>
      parseEnrollmentCompletion({ ...p, providerSessionId: "801" }, id, { challengeId: challenge, sessionId: "800" }),
    ).toThrow();
  });
  it.each(["current", "complete"] as const)(
    "uses exact canonical private HTTP base for %s while the token remains TLS",
    async (operation) => {
      vi.stubEnv("PAYPM_WORKFORCE_IDENTITY_URL", "http://heritagepay-identity-api.identity.svc.cluster.local:3000/api");
      const result = operation === "current" ? projection() : completion();
      const fetch = vi
        .fn()
        .mockResolvedValueOnce(Response.json({ access_token: "private-token", token_type: "Bearer" }))
        .mockResolvedValueOnce(Response.json(result));
      vi.stubGlobal("fetch", fetch);
      const body = operation === "current" ? {} : { challengeId: challenge, sessionId: "800" };
      expect(await enrollmentIdentityRequest(operation, id, body)).toEqual(result);
      expect(fetch).toHaveBeenCalledTimes(2);
      expect(String(fetch.mock.calls[0][0])).toBe("https://auth.paypm.test/oauth/v2/token");
      expect(String(fetch.mock.calls[1][0])).toBe(
        `http://heritagepay-identity-api.identity.svc.cluster.local:3000/api/internal/v1/reviewed-workforce-enrollments/${id}/${operation}`,
      );
      expect(fetch.mock.calls[1][1]).toMatchObject({
        method: "POST",
        cache: "no-store",
        redirect: "error",
        body: JSON.stringify(body),
        headers: { authorization: "Bearer private-token", "content-type": "application/json" },
      });
      expect(fetch.mock.calls[0][1].signal).toBe(fetch.mock.calls[1][1].signal);
    },
  );
  it.each([
    "http://heritagepay-identity-api.identity.svc.cluster.local/api",
    "http://heritagepay-identity-api.identity.svc.cluster.local:80/api",
    "http://heritagepay-identity-api.identity.svc.cluster.local:3001/api",
    "http://heritagepay-identity-api.identity.svc.cluster.local:03000/api",
    "http://heritagepay-identity-api.identity.svc.cluster.local:3000/",
    "http://heritagepay-identity-api.identity.svc.cluster.local:3000/api/",
    "http://heritagepay-identity-api.identity.svc.cluster.local:3000/api/current",
    "http://heritagepay-identity-api.identity.svc.cluster.local:3000/api/../api",
    "http://heritagepay-identity-api.identity.svc.cluster.local:3000/%61pi",
    "http://heritagepay-identity-api.identity.svc.cluster.local:3000/api?",
    "http://heritagepay-identity-api.identity.svc.cluster.local:3000/api?x=1",
    "http://heritagepay-identity-api.identity.svc.cluster.local:3000/api#",
    "http://heritagepay-identity-api.identity.svc.cluster.local:3000/api#x",
    "http://user@heritagepay-identity-api.identity.svc.cluster.local:3000/api",
    "http://user:password@heritagepay-identity-api.identity.svc.cluster.local:3000/api",
    "http://@heritagepay-identity-api.identity.svc.cluster.local:3000/api",
    "http://heritagepay-identity-api.identity.svc.cluster.local.:3000/api",
    "http://HERITAGEPAY-IDENTITY-API.identity.svc.cluster.local:3000/api",
    "HTTP://heritagepay-identity-api.identity.svc.cluster.local:3000/api",
    " http://heritagepay-identity-api.identity.svc.cluster.local:3000/api",
    "http://heritagepay-identity-api.identity.svc.cluster.local:3000/api ",
    "http://heritagepay-identity-api.identity.svc:3000/api",
    "http://heritagepay-identity-api:3000/api",
    "http://heritagepay-identity-api.other.svc.cluster.local:3000/api",
    "http://heritagepay-identity-api.identity.svc.cluster.local.evil.test:3000/api",
    "http://identity.paypm.test:3000/api",
    "http://127.0.0.1:3000/api",
    "http://localhost:3000/api",
    "http://[::1]:3000/api",
    "//heritagepay-identity-api.identity.svc.cluster.local:3000/api",
    "ftp://heritagepay-identity-api.identity.svc.cluster.local:3000/api",
  ])("rejects neighboring or normalized HTTP base %s before any token request", async (base) => {
    vi.stubEnv("PAYPM_WORKFORCE_IDENTITY_URL", base);
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    await expect(enrollmentIdentityRequest("current", id)).rejects.toThrow();
    expect(fetch).not.toHaveBeenCalled();
  });
  it.each(["http://heritagepay-identity-api.identity.svc.cluster.local:3000/api", "http://auth.paypm.test/oauth/v2/token"])(
    "never extends the HTTP exception to token URL %s",
    async (tokenUrl) => {
      vi.stubEnv("PAYPM_WORKFORCE_IDENTITY_URL", "http://heritagepay-identity-api.identity.svc.cluster.local:3000/api");
      vi.stubEnv("PAYPM_WORKFORCE_IDENTITY_TOKEN_URL", tokenUrl);
      const fetch = vi.fn();
      vi.stubGlobal("fetch", fetch);
      await expect(enrollmentIdentityRequest("current", id)).rejects.toThrow();
      expect(fetch).not.toHaveBeenCalled();
    },
  );
  it("preserves the existing HTTPS base trailing-slash behavior", async () => {
    vi.stubEnv("PAYPM_WORKFORCE_IDENTITY_URL", "https://identity.paypm.test/api/");
    const p = projection();
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(Response.json({ access_token: "private-token", token_type: "Bearer" }))
      .mockResolvedValueOnce(Response.json(p));
    vi.stubGlobal("fetch", fetch);
    expect(await enrollmentIdentityRequest("current", id)).toEqual(p);
    expect(String(fetch.mock.calls[1][0])).toBe(
      `https://identity.paypm.test/api/internal/v1/reviewed-workforce-enrollments/${id}/current`,
    );
  });
});
