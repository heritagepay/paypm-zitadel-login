// @vitest-environment node
import { randomUUID } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { workforceAssertionHash } from "./workforce-assertion";
import { readCurrentWorkforceEnrollment } from "./workforce-enrollment-reader";
import { workforceEnrollmentStore } from "./workforce-enrollment-store";
import { workforceProvider } from "./workforce-provider";
vi.mock("next/headers", () => ({ headers: vi.fn(async () => new Headers()) }));
vi.mock("./service-url", () => ({ getServiceConfig: () => ({ serviceConfig: { baseUrl: "https://auth.paypm.test" } }) }));
vi.mock("./workforce-enrollment-store", () => ({ workforceEnrollmentStore: vi.fn() }));
vi.mock("./workforce-provider", () => ({ workforceProvider: vi.fn() }));
const runtime = { sourceRevision: "a".repeat(40), imageDigest: "b".repeat(64), configurationSha256: "c".repeat(64) },
  secret = "reader-synthetic-token-only-".repeat(2);
let ceremony: any, store: any, provider: any, session: any;
const ts = (ms: number) => ({ seconds: BigInt(Math.floor(ms / 1000)), nanos: (ms % 1000) * 1000000 });
const request = (body: any = { enrollmentId: ceremony.enrollmentId }, extra: any = {}) =>
  new Request("https://auth.paypm.test/api/internal/v1/workforce/enrollments/current", {
    method: "POST",
    headers: { authorization: "Bearer " + secret, ...extra },
    body: JSON.stringify(body),
  });
beforeEach(() => {
  vi.resetAllMocks();
  for (const [k, v] of Object.entries({
    PAYPM_WORKFORCE_ISSUER: "https://auth.paypm.test",
    PAYPM_WORKFORCE_ORGANIZATION_ID: "300",
    PAYPM_WORKFORCE_OIDC_CLIENT_IDS: "staff-client",
    PAYPM_WORKFORCE_EMAIL_OTP_READY: "true",
    PAYPM_WORKFORCE_ENROLLMENT_RUNTIME_JSON: JSON.stringify(runtime),
    PAYPM_WORKFORCE_ENROLLMENT_CEREMONY_READER_TOKEN: secret,
  }))
    vi.stubEnv(k, v);
  const now = Date.now();
  ceremony = {
    enrollmentId: randomUUID(),
    personId: randomUUID(),
    policyId: randomUUID(),
    issuer: "https://auth.paypm.test",
    organizationId: "300",
    clientId: "staff-client",
    providerSubject: "700",
    sessionId: "800",
    challengeId: randomUUID(),
    epoch: "0",
    issuedAt: new Date(now - 5000).toISOString(),
    expiresAt: new Date(now + 120000).toISOString(),
    ...runtime,
  };
  session = {
    id: "800",
    creationDate: ts(now - 5000),
    expirationDate: ts(now + 120000),
    metadata: {
      ["paypm_workforce_enrollment_" + ceremony.challengeId]: new TextEncoder().encode(workforceAssertionHash(ceremony)),
    },
    factors: { otpEmail: { verifiedAt: ts(now - 1000) } },
  };
  store = {
    ceremony: vi.fn(async () => ceremony),
    base: {
      currentEnrollmentChallenge: vi.fn(async () => ({ id: ceremony.challengeId, verified_at: new Date(now - 1000) })),
    },
  };
  provider = { read: vi.fn(async () => session) };
  vi.mocked(workforceEnrollmentStore).mockReturnValue(store);
  vi.mocked(workforceProvider).mockResolvedValue(provider);
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.useRealTimers();
});
describe("private purpose-restricted live ceremony readback", () => {
  it("returns exact ceremony only after actual native OTP and final current epoch proof", async () => {
    const r = await readCurrentWorkforceEnrollment(request());
    expect(r.status).toBe(200);
    expect(r.headers.get("cache-control")).toBe("no-store");
    expect(await r.json()).toEqual(ceremony);
    expect(store.ceremony).toHaveBeenCalledTimes(2);
    expect(provider.read).toHaveBeenCalledOnce();
  });
  it.each(["off", "browser-origin", "browser-cookie", "wrong-bearer", "extra-field", "large-body", "reused-key"])(
    "denies %s before provider read",
    async (kind) => {
      let extra: any = {},
        body: any = { enrollmentId: ceremony.enrollmentId };
      if (kind === "off") vi.stubEnv("PAYPM_WORKFORCE_ENROLLMENT_RUNTIME_JSON", "");
      if (kind === "browser-origin") extra.origin = "https://auth.paypm.test";
      if (kind === "browser-cookie") extra.cookie = "signed=anything";
      if (kind === "wrong-bearer") extra.authorization = "Bearer wrong";
      if (kind === "extra-field") body.personId = randomUUID();
      if (kind === "large-body") body.padding = "x".repeat(4097);
      if (kind === "reused-key") vi.stubEnv("PAYPM_IDENTITY_ACTION_RECEIPT_READER_TOKEN", secret);
      expect((await readCurrentWorkforceEnrollment(request(body, extra))).status).toBe(403);
      expect(provider.read).not.toHaveBeenCalled();
    },
  );
  it.each(["wrong-source", "wrong-client", "metadata", "no-factor", "stale-factor", "retired-final"])(
    "denies %s",
    async (kind) => {
      if (kind === "wrong-source") ceremony.sourceRevision = "d".repeat(40);
      if (kind === "wrong-client") ceremony.clientId = "other";
      if (kind === "metadata") session.metadata = {};
      if (kind === "no-factor") session.factors = {};
      if (kind === "stale-factor") session.factors.otpEmail.verifiedAt = ts(Date.now() - 100000);
      if (kind === "retired-final")
        store.ceremony.mockResolvedValueOnce(ceremony).mockRejectedValueOnce(new Error("epoch retired"));
      expect((await readCurrentWorkforceEnrollment(request())).status).toBe(403);
    },
  );
  it("caps the whole body/provider/final-read time budget", async () => {
    vi.useFakeTimers();
    provider.read.mockImplementation(() => new Promise(() => {}));
    const pending = readCurrentWorkforceEnrollment(request());
    await vi.advanceTimersByTimeAsync(8001);
    expect((await pending).status).toBe(403);
  });
});
