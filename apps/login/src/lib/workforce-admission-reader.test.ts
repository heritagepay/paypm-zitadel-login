import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { readCurrentWorkforceAdmission } from "./workforce-admission-reader";
import { workforceProvider } from "./workforce-provider";
import { workforceStore } from "./workforce-store";
vi.mock("next/headers", () => ({ headers: vi.fn(() => new Headers()) }));
vi.mock("./service-url", () => ({ getServiceConfig: () => ({ serviceConfig: { baseUrl: "https://auth.paypm.test" } }) }));
vi.mock("./workforce-store", () => ({ workforceStore: vi.fn() }));
vi.mock("./workforce-provider", () => ({ workforceProvider: vi.fn() }));
const tuple = { issuer: "https://auth.paypm.test", providerSubject: "700", baseSessionId: "900", clientId: "staff" };
let store: any, provider: any;
const key = Buffer.alloc(32, 29).toString("base64");
const call = (input: any = tuple, secret = key) =>
  readCurrentWorkforceAdmission(
    new Request("https://login.paypm.test/api/internal/v1/workforce/admissions/check", {
      method: "POST",
      headers: { authorization: "Bearer " + secret, "content-type": "application/json" },
      body: JSON.stringify(input),
    }),
  );
beforeEach(() => {
  vi.resetAllMocks();
  vi.stubEnv("PAYPM_WORKFORCE_ORGANIZATION_ID", "300");
  vi.stubEnv("PAYPM_WORKFORCE_ISSUER", tuple.issuer);
  vi.stubEnv("PAYPM_WORKFORCE_OIDC_CLIENT_IDS", "staff");
  vi.stubEnv("PAYPM_WORKFORCE_EMAIL_OTP_READY", "true");
  vi.stubEnv("PAYPM_WORKFORCE_OIDC_ADMISSION_POLICIES_JSON", JSON.stringify([{ clientId: "staff", mode: "limited" }]));
  vi.stubEnv("PAYPM_WORKFORCE_ADMISSION_READER_TOKEN", key);
  const verifiedAt = new Date(Date.now() - 1000),
    n = verifiedAt.getTime(),
    ts = (off: number) => ({ seconds: BigInt(Math.floor((n + off) / 1000)), nanos: ((n + off) % 1000) * 1000000 });
  store = {
    currentAdmission: vi.fn(async () => ({
      request_id: "oidc_owned",
      challenge_id: "ad067362-c41b-4c15-8645-64be64eebf9c",
      epoch: "2",
      verified_at: verifiedAt,
      absolute_expires_at: new Date(Date.now() + 300000),
    })),
    challenge: vi.fn(),
  };
  provider = {
    read: vi.fn(async () => ({
      id: "900",
      creationDate: ts(-5000),
      expirationDate: ts(300000),
      factors: { user: { id: "700" }, otpEmail: { verifiedAt: ts(0) } },
    })),
  };
  vi.mocked(workforceStore).mockReturnValue(store);
  vi.mocked(workforceProvider).mockResolvedValue(provider);
});
afterEach(() => vi.unstubAllEnvs());
describe("private current workforce admission producer", () => {
  it("returns only exact current provider and durable admission under the separate machine credential", async () => {
    const response = await call();
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      active: true,
      ...tuple,
      revocationVersion: "2",
      authenticationClass: "workforce_limited",
    });
    expect(store.currentAdmission).toHaveBeenCalledTimes(2);
  });
  it.each(["wrong-secret", "actor-header", "other-client", "other-issuer", "revoked", "late-logout", "provider-outage"])(
    "denies %s at the private boundary",
    async (kind) => {
      if (kind === "revoked") store.currentAdmission.mockResolvedValue(undefined);
      if (kind === "late-logout")
        store.currentAdmission
          .mockResolvedValueOnce({
            request_id: "oidc_owned",
            challenge_id: "ad067362-c41b-4c15-8645-64be64eebf9c",
            epoch: "2",
            verified_at: new Date(Date.now() - 1000),
            absolute_expires_at: new Date(Date.now() + 300000),
          })
          .mockResolvedValue(undefined);
      if (kind === "provider-outage") provider.read.mockRejectedValue(new Error("unavailable"));
      const input =
        kind === "actor-header"
          ? { ...tuple, actorId: "700" }
          : kind === "other-client"
            ? { ...tuple, clientId: "other" }
            : kind === "other-issuer"
              ? { ...tuple, issuer: "https://evil.test" }
              : tuple;
      const response = await call(input, kind === "wrong-secret" ? "wrong" : key);
      expect(response.status).toBe(403);
      expect(await response.json()).toEqual({ active: false });
    },
  );
});
