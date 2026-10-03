import { UserState } from "@zitadel/proto/zitadel/user/v2/user_pb";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loginWithOIDCAndSession } from "./oidc";
import { readWorkforceState } from "./workforce-state";
import { workforceStore } from "./workforce-store";
import { createCallback, getAuthRequest, getUserByID } from "./zitadel";
vi.mock("./zitadel", () => ({
  getAuthRequest: vi.fn(),
  getUserByID: vi.fn(),
  createCallback: vi.fn(),
  getLoginSettings: vi.fn(),
}));
vi.mock("./session", () => ({ isSessionValid: vi.fn(async () => true) }));
vi.mock("./server/loginname", () => ({ sendLoginname: vi.fn() }));
vi.mock("./workforce-state", () => ({ readWorkforceState: vi.fn() }));
vi.mock("./workforce-store", () => ({ workforceStore: vi.fn() }));
const ts = (offset: number) => {
  const n = Date.now() + offset;
  return { seconds: BigInt(Math.floor(n / 1000)), nanos: (n % 1000) * 1000000 };
};
let session: any, request: any, admission: any, store: any;
const call = () =>
  loginWithOIDCAndSession({
    serviceConfig: { baseUrl: "https://auth.paypm.test" },
    authRequest: "owned",
    sessionId: "actual-session",
    sessions: [session],
    sessionCookies: [{ id: "actual-session", token: "private-provider-token" } as any],
  });
beforeEach(() => {
  vi.resetAllMocks();
  for (const [k, v] of Object.entries({
    PAYPM_WORKFORCE_ORGANIZATION_ID: "300",
    PAYPM_WORKFORCE_ISSUER: "https://auth.paypm.test",
    PAYPM_WORKFORCE_OIDC_CLIENT_IDS: "registered-console",
    PAYPM_WORKFORCE_OIDC_ADMISSION_POLICIES_JSON: JSON.stringify([{ clientId: "registered-console", mode: "limited" }]),
    PAYPM_WORKFORCE_EMAIL_OTP_READY: "true",
    PAYPM_WORKFORCE_BOOTSTRAP_MODE: "qualification",
    PAYPM_WORKFORCE_BOOTSTRAP_INVITED_USER_IDS: "700",
  }))
    vi.stubEnv(k, v);
  session = {
    id: "actual-session",
    creationDate: ts(-5000),
    expirationDate: ts(28000000),
    factors: { user: { id: "700", organizationId: "300", verifiedAt: ts(-4000) }, otpEmail: { verifiedAt: ts(-2000) } },
  };
  request = { clientId: "registered-console", creationDate: ts(-1000), prompt: [] };
  admission = {
    purpose: "limited-admission",
    challengeId: "ad067362-c41b-4c15-8645-64be64eebf9c",
    sessionId: "actual-session",
    userId: "700",
    clientId: "registered-console",
    requestId: "oidc_owned",
    issuedAt: Date.now() - 5000,
    expiresAt: Date.now() + 28000000,
  };
  store = { admission: vi.fn(async () => true) };
  vi.mocked(workforceStore).mockReturnValue(store);
  vi.mocked(getAuthRequest).mockResolvedValue({ authRequest: request } as any);
  vi.mocked(readWorkforceState).mockImplementation(async () => admission);
  vi.mocked(getUserByID).mockResolvedValue({
    user: {
      userId: "700",
      state: UserState.ACTIVE,
      details: { resourceOwner: "300" },
      type: { case: "human", value: { email: { email: "staff@example.test", isVerified: true } } },
    },
  } as any);
  vi.mocked(createCallback).mockResolvedValue({ callbackUrl: "https://console.example.test/callback" } as any);
});
afterEach(() => vi.unstubAllEnvs());
describe("exact workforce OIDC category admission", () => {
  it("admits only the registered limited client using its current durable exact session", async () => {
    expect(await call()).toHaveProperty("redirect");
    expect(store.admission).toHaveBeenCalledWith("actual-session", "700", "registered-console", "oidc_owned");
  });
  it.each(["no-policy", "wrong-user", "wrong-client", "wrong-request", "missing-durable-binding", "revoked"])(
    "rejects %s before provider callback",
    async (kind) => {
      if (kind === "no-policy") vi.stubEnv("PAYPM_WORKFORCE_OIDC_ADMISSION_POLICIES_JSON", "");
      if (kind === "wrong-user") admission.userId = "900";
      if (kind === "wrong-client") admission.clientId = "other";
      if (kind === "wrong-request") admission.requestId = "oidc_other";
      if (kind === "missing-durable-binding") delete admission.challengeId;
      if (kind === "revoked") store.admission.mockResolvedValue(false);
      expect(await call()).toHaveProperty("error");
      expect(createCallback).not.toHaveBeenCalled();
    },
  );
  it.each(["missing", "missing-uv", "stale", "before-request", "absent-request-time"])(
    "rejects privileged %s passkey evidence",
    async (kind) => {
      vi.stubEnv(
        "PAYPM_WORKFORCE_OIDC_ADMISSION_POLICIES_JSON",
        JSON.stringify([{ clientId: "registered-console", mode: "fresh_passkey" }]),
      );
      session.factors.webAuthN = { userVerified: true, verifiedAt: ts(0) };
      if (kind === "missing") delete session.factors.webAuthN;
      if (kind === "missing-uv") session.factors.webAuthN.userVerified = false;
      if (kind === "stale") session.factors.webAuthN.verifiedAt = ts(-61000);
      if (kind === "before-request") session.factors.webAuthN.verifiedAt = ts(-1500);
      if (kind === "absent-request-time") delete request.creationDate;
      expect(await call()).toHaveProperty("error");
      expect(createCallback).not.toHaveBeenCalled();
    },
  );
  it("requires real fresh verified UV completion after the exact privileged request", async () => {
    vi.stubEnv(
      "PAYPM_WORKFORCE_OIDC_ADMISSION_POLICIES_JSON",
      JSON.stringify([{ clientId: "registered-console", mode: "fresh_passkey" }]),
    );
    session.factors.webAuthN = { userVerified: true, verifiedAt: ts(0) };
    expect(await call()).toHaveProperty("redirect");
  });
  it("preserves existing privileged admission when OTP readiness is disabled", async () => {
    vi.stubEnv("PAYPM_WORKFORCE_EMAIL_OTP_READY", "false");
    vi.stubEnv("PAYPM_WORKFORCE_OIDC_ADMISSION_POLICIES_JSON", "");
    admission = undefined;
    expect(await call()).toHaveProperty("redirect");
    expect(store.admission).not.toHaveBeenCalled();
  });
});
