import { Prompt } from "@zitadel/proto/zitadel/oidc/v2/authorization_pb";
import { UserState } from "@zitadel/proto/zitadel/user/v2/user_pb";
import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { findValidSession, isSessionValid } from "../session";
import { readWorkforceState } from "../workforce-state";
import { workforceStore } from "../workforce-store";
import { createCallback, getAuthRequest, getUserByID } from "../zitadel";
import { handleOIDCFlowInitiation } from "./flow-initiation";
import { sendLoginname } from "./loginname";

vi.mock("./workforce-enrollment", () => ({ resumeReviewedWorkforceEnrollmentRequest: vi.fn() }));
vi.mock("../cookies", () => ({ getLanguageCookie: vi.fn(), setLanguageCookie: vi.fn() }));
vi.mock("./loginname", () => ({ sendLoginname: vi.fn() }));
vi.mock("./host", () => ({
  getPublicHost: () => "auth.example.test",
  getInstanceHost: vi.fn(),
}));
vi.mock("../session", () => ({ findValidSession: vi.fn(), isSessionValid: vi.fn() }));
vi.mock("../workforce-state", () => ({ readWorkforceState: vi.fn() }));
vi.mock("../workforce-store", () => ({ workforceStore: vi.fn() }));
vi.mock("../zitadel", () => ({
  createCallback: vi.fn(),
  getAuthRequest: vi.fn(),
  getUserByID: vi.fn(),
  getLoginSettings: vi.fn(),
  getSecuritySettings: vi.fn(),
  createResponse: vi.fn(),
  getActiveIdentityProviders: vi.fn(),
  getOrgsByDomain: vi.fn(),
  getSAMLRequest: vi.fn(),
  startIdentityProviderFlow: vi.fn(),
}));

const time = (offset: number) => {
  const value = Date.now() + offset;
  return { seconds: BigInt(Math.floor(value / 1000)), nanos: (value % 1000) * 1000000 };
};
let session: any, request: any, admission: any, store: any;
const cookie = { id: "session-700", token: "synthetic-provider-token" };
const call = () =>
  handleOIDCFlowInitiation({
    serviceConfig: { baseUrl: "https://auth.example.test" },
    requestId: "oidc_owned",
    sessions: [session],
    sessionCookies: [cookie],
    request: new NextRequest("https://auth.example.test/ui/v2/login?requestId=oidc_owned"),
  });
beforeEach(() => {
  vi.resetAllMocks();
  for (const [name, value] of Object.entries({
    NEXT_PUBLIC_BASE_PATH: "/ui/v2/login",
    PAYPM_WORKFORCE_ORGANIZATION_ID: "300",
    PAYPM_WORKFORCE_ISSUER: "https://auth.example.test",
    PAYPM_WORKFORCE_OIDC_CLIENT_IDS: "staff-client",
    PAYPM_WORKFORCE_EMAIL_OTP_READY: "true",
    PAYPM_WORKFORCE_OIDC_ADMISSION_POLICIES_JSON: JSON.stringify([{ clientId: "staff-client", mode: "limited" }]),
    PAYPM_WORKFORCE_BOOTSTRAP_MODE: "qualification",
    PAYPM_WORKFORCE_BOOTSTRAP_INVITED_USER_IDS: "700",
  }))
    vi.stubEnv(name, value);
  session = {
    id: cookie.id,
    creationDate: time(-5000),
    expirationDate: time(28000000),
    factors: {
      user: { id: "700", organizationId: "300", verifiedAt: time(-4000) },
      password: { verifiedAt: time(-3000) },
      otpEmail: { verifiedAt: time(-2000) },
    },
  };
  request = { id: "owned", clientId: "staff-client", prompt: [], uiLocales: [], scope: [], creationDate: time(-1000) };
  admission = {
    purpose: "limited-admission",
    challengeId: "ad067362-c41b-4c15-8645-64be64eebf9c",
    sessionId: cookie.id,
    userId: "700",
    clientId: "staff-client",
    requestId: "oidc_owned",
    issuedAt: Date.now() - 5000,
    expiresAt: Date.now() + 28000000,
  };
  store = { admission: vi.fn(async () => true) };
  vi.mocked(workforceStore).mockReturnValue(store);
  vi.mocked(readWorkforceState).mockImplementation(async () => admission);
  vi.mocked(findValidSession).mockImplementation(async () => session);
  vi.mocked(isSessionValid).mockResolvedValue(true);
  vi.mocked(getAuthRequest).mockImplementation(async () => ({ authRequest: request }) as any);
  vi.mocked(getUserByID).mockResolvedValue({
    user: {
      userId: "700",
      state: UserState.ACTIVE,
      details: { resourceOwner: "300" },
      type: { case: "human", value: { email: { email: "staff@example.test", isVerified: true } } },
    },
  } as any);
  vi.mocked(createCallback).mockResolvedValue({ callbackUrl: "https://identity.example.test/callback" } as any);
});
afterEach(() => vi.unstubAllEnvs());

describe.each(["silent", "default"] as const)("native %s workforce callback", (kind) => {
  beforeEach(() => {
    request.prompt = kind === "silent" ? [Prompt.NONE] : [];
  });
  it.each([
    "no-policy",
    "no-admission",
    "wrong-user",
    "wrong-client",
    "wrong-request",
    "revoked",
    "ineligible",
    "wrong-organization",
  ])("a generally valid session cannot bypass %s", async (failure) => {
    if (failure === "no-policy") vi.stubEnv("PAYPM_WORKFORCE_OIDC_ADMISSION_POLICIES_JSON", "");
    if (failure === "no-admission") admission = undefined;
    if (failure === "wrong-user") admission.userId = "900";
    if (failure === "wrong-client") admission.clientId = "another-client";
    if (failure === "wrong-request") admission.requestId = "oidc_another";
    if (failure === "revoked") store.admission.mockResolvedValue(false);
    if (failure === "ineligible") vi.mocked(getUserByID).mockResolvedValue({ user: { state: UserState.INACTIVE } } as any);
    if (failure === "wrong-organization") session.factors.user.organizationId = "900";
    const response = await call();
    expect(createCallback).not.toHaveBeenCalled();
    if (kind === "silent") expect(response.status).toBe(400);
    else
      expect(response.headers.get("location")).toBe("https://auth.example.test/ui/v2/login/accounts?requestId=oidc_owned");
  });
  it.each(["missing", "no-uv", "stale", "before-request"])("requires fresh privileged %s evidence", async (failure) => {
    vi.stubEnv(
      "PAYPM_WORKFORCE_OIDC_ADMISSION_POLICIES_JSON",
      JSON.stringify([{ clientId: "staff-client", mode: "fresh_passkey" }]),
    );
    session.factors.webAuthN = { userVerified: true, verifiedAt: time(0) };
    if (failure === "missing") delete session.factors.webAuthN;
    if (failure === "no-uv") session.factors.webAuthN.userVerified = false;
    if (failure === "stale") session.factors.webAuthN.verifiedAt = time(-61000);
    if (failure === "before-request") session.factors.webAuthN.verifiedAt = time(-1500);
    await call();
    expect(createCallback).not.toHaveBeenCalled();
  });
  it("allows only the exact current durable limited admission", async () => {
    const response = await call();
    expect(response.headers.get("location")).toBe("https://identity.example.test/callback");
    expect(store.admission).toHaveBeenCalledWith(cookie.id, "700", "staff-client", "oidc_owned");
    expect(createCallback).toHaveBeenCalledOnce();
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
  });
  it("fails closed when the durable admission read is unavailable", async () => {
    store.admission.mockRejectedValue(new Error("synthetic admission outage"));
    const response = await call();
    expect(createCallback).not.toHaveBeenCalled();
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
    if (kind === "silent") expect(response.status).toBe(400);
    else
      expect(response.headers.get("location")).toBe("https://auth.example.test/ui/v2/login/accounts?requestId=oidc_owned");
  });
  it("permits fresh provider-verified UV after the privileged request", async () => {
    vi.stubEnv(
      "PAYPM_WORKFORCE_OIDC_ADMISSION_POLICIES_JSON",
      JSON.stringify([{ clientId: "staff-client", mode: "fresh_passkey" }]),
    );
    session.factors.webAuthN = { userVerified: true, verifiedAt: time(0) };
    expect((await call()).headers.get("location")).toBe("https://identity.example.test/callback");
    expect(store.admission).toHaveBeenCalledOnce();
  });
  it("preserves non-workforce provider callbacks", async () => {
    request.clientId = "other-client";
    expect((await call()).headers.get("location")).toBe("https://identity.example.test/callback");
    expect(store.admission).not.toHaveBeenCalled();
  });
  it("preserves registered native callback schemes", async () => {
    vi.mocked(createCallback).mockResolvedValue({ callbackUrl: "paypm-demo://callback?code=synthetic-code" } as any);
    expect((await call()).headers.get("location")).toBe("paypm-demo://callback?code=synthetic-code");
  });
  it("rechecks validity before provider completion", async () => {
    vi.mocked(isSessionValid).mockResolvedValue(false);
    vi.mocked(sendLoginname).mockResolvedValue({ redirect: "/loginname?requestId=oidc_owned" });
    const response = await call();
    expect(createCallback).not.toHaveBeenCalled();
    if (kind === "silent") {
      expect(sendLoginname).not.toHaveBeenCalled();
      expect(response.status).toBe(400);
    } else {
      expect(sendLoginname).toHaveBeenCalledOnce();
      expect(response.headers.get("location")).toBe("https://auth.example.test/ui/v2/login/loginname?requestId=oidc_owned");
    }
  });
});
