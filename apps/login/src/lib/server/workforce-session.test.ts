import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getSessionCookieById, removeSessionFromCookie } from "../cookies";
import { workforceEligible } from "../workforce-policy";
import { workforceProvider } from "../workforce-provider";
import { deleteWorkforceState, readWorkforceState } from "../workforce-state";
import { workforceStore } from "../workforce-store";
import { getSession, getUserByID } from "../zitadel";
import { logoutAllWorkforceSessions } from "./workforce-session";
vi.mock("next/headers", () => ({ headers: vi.fn(() => new Headers()) }));
vi.mock("../service-url", () => ({ getServiceConfig: () => ({ serviceConfig: { baseUrl: "https://auth.paypm.test" } }) }));
vi.mock("../cookies", () => ({ getSessionCookieById: vi.fn(), removeSessionFromCookie: vi.fn() }));
vi.mock("../workforce-state", () => ({ readWorkforceState: vi.fn(), deleteWorkforceState: vi.fn() }));
vi.mock("../workforce-store", () => ({ workforceStore: vi.fn() }));
vi.mock("../workforce-provider", () => ({ workforceProvider: vi.fn() }));
vi.mock("../workforce-policy", async (original) => ({
  ...(await original<typeof import("../workforce-policy")>()),
  workforceEligible: vi.fn(),
}));
vi.mock("../zitadel", () => ({ getSession: vi.fn(), getUserByID: vi.fn() }));
let store: any, provider: any;
const ts = (off: number) => ({ seconds: BigInt(Math.floor((Date.now() + off) / 1000)), nanos: 0 });
beforeEach(() => {
  vi.resetAllMocks();
  vi.stubEnv("PAYPM_WORKFORCE_ORGANIZATION_ID", "300");
  vi.stubEnv("PAYPM_WORKFORCE_ISSUER", "https://auth.paypm.test");
  vi.stubEnv("PAYPM_WORKFORCE_OIDC_CLIENT_IDS", "staff");
  vi.stubEnv("PAYPM_WORKFORCE_OIDC_ADMISSION_POLICIES_JSON", JSON.stringify([{ clientId: "staff", mode: "limited" }]));
  vi.stubEnv("PAYPM_WORKFORCE_EMAIL_OTP_READY", "true");
  vi.mocked(readWorkforceState).mockResolvedValue({
    purpose: "limited-admission",
    challengeId: "ad067362-c41b-4c15-8645-64be64eebf9c",
    sessionId: "123",
    userId: "700",
    clientId: "staff",
    requestId: "oidc_owned",
    issuedAt: Date.now() - 5000,
    expiresAt: Date.now() + 200000,
  });
  vi.mocked(getSessionCookieById).mockResolvedValue({ id: "123", token: "private", requestId: "oidc_owned" } as any);
  vi.mocked(getSession).mockResolvedValue({
    session: {
      id: "123",
      creationDate: ts(-5000),
      expirationDate: ts(200000),
      factors: { user: { id: "700", organizationId: "300" }, otpEmail: { verifiedAt: ts(-1000) } },
    },
  } as any);
  vi.mocked(getUserByID).mockResolvedValue({ user: { userId: "700" } } as any);
  vi.mocked(workforceEligible).mockResolvedValue(true);
  store = {
    admission: vi.fn(async () => true),
    revokeUser: vi.fn(),
    pendingRevocations: vi.fn(async () => [{ provider_session_id: "123" }, { provider_session_id: "456" }]),
    revocationCompleted: vi.fn(),
  };
  provider = { revoke: vi.fn() };
  vi.mocked(workforceStore).mockReturnValue(store);
  vi.mocked(workforceProvider).mockResolvedValue(provider);
});
afterEach(() => vi.unstubAllEnvs());
describe("Login-owned logout-all", () => {
  it("tombstones all subject admissions and clears browser proof before provider deletion", async () => {
    expect(await logoutAllWorkforceSessions()).toEqual({ revoked: true });
    expect(store.revokeUser).toHaveBeenCalledWith("https://auth.paypm.test", "700");
    expect(store.revokeUser.mock.invocationCallOrder[0]).toBeLessThan(provider.revoke.mock.invocationCallOrder[0]);
    expect(deleteWorkforceState).toHaveBeenCalled();
    expect(removeSessionFromCookie).toHaveBeenCalled();
    expect(store.revocationCompleted).toHaveBeenCalledTimes(2);
  });
  it("reports pending provider cleanup without reopening local admission", async () => {
    provider.revoke.mockRejectedValue(new Error("provider unavailable"));
    expect(await logoutAllWorkforceSessions()).toHaveProperty("error");
    expect(store.revokeUser).toHaveBeenCalled();
    expect(deleteWorkforceState).toHaveBeenCalled();
    expect(store.revocationCompleted).not.toHaveBeenCalled();
  });
  it("denies unadmitted or revoked subject input before any provider effect", async () => {
    store.admission.mockResolvedValue(false);
    expect(await logoutAllWorkforceSessions()).toHaveProperty("error");
    expect(store.revokeUser).not.toHaveBeenCalled();
    expect(provider.revoke).not.toHaveBeenCalled();
  });
});
