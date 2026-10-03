import { UserState } from "@zitadel/proto/zitadel/user/v2/user_pb";
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { completeFlowOrGetUrl } from "../client";
import { getSessionCookieById } from "../cookies";
import { readWorkforceState, writeWorkforceState } from "../workforce-state";
import {
  getAuthRequest,
  getLoginSettings,
  getSession,
  getUserByID,
  listAuthenticationMethodTypes,
  listUsers,
} from "../zitadel";
import { createSessionAndUpdateCookie, setSessionAndUpdateCookie } from "./cookie";
import { startWorkforceEmailOtp, verifyWorkforceEmailOtp } from "./workforce-email";
vi.mock("next/headers", () => ({ headers: vi.fn(() => new Headers()) }));
vi.mock("../service-url", () => ({ getServiceConfig: () => ({ serviceConfig: { baseUrl: "https://auth.example.com" } }) }));
vi.mock("../zitadel", () => ({
  getAuthRequest: vi.fn(),
  getLoginSettings: vi.fn(),
  getSession: vi.fn(),
  getUserByID: vi.fn(),
  listAuthenticationMethodTypes: vi.fn(),
  listUsers: vi.fn(),
}));
vi.mock("./cookie", () => ({ createSessionAndUpdateCookie: vi.fn(), setSessionAndUpdateCookie: vi.fn() }));
vi.mock("../cookies", () => ({ getSessionCookieById: vi.fn() }));
vi.mock("../workforce-state", async (original) => ({
  ...(await original<typeof import("../workforce-state")>()),
  readWorkforceState: vi.fn(),
  writeWorkforceState: vi.fn(),
}));
vi.mock("../client", () => ({ completeFlowOrGetUrl: vi.fn() }));

const timestamp = (offset: number) => ({ seconds: BigInt(Math.floor((Date.now() + offset) / 1000)), nanos: 0 });
const user = {
  userId: "12345",
  state: UserState.ACTIVE,
  details: { resourceOwner: "54321" },
  type: { case: "human", value: { email: { email: "staff@example.com", isVerified: true } } },
} as any;
const session = () =>
  ({
    id: "provider-session",
    creationDate: timestamp(-1000),
    expirationDate: timestamp(28800000),
    factors: {
      user: { id: "12345", organizationId: "54321", loginName: "staff@example.com", verifiedAt: timestamp(-1000) },
    },
  }) as any;
beforeEach(() => {
  vi.resetAllMocks();
  vi.stubEnv("PAYPM_WORKFORCE_ORGANIZATION_ID", "54321");
  vi.stubEnv("PAYPM_WORKFORCE_ISSUER", "https://auth.example.com");
  vi.stubEnv("PAYPM_WORKFORCE_OIDC_CLIENT_IDS", "workforce-client");
  vi.stubEnv("PAYPM_WORKFORCE_EMAIL_OTP_READY", "true");
  vi.stubEnv("PAYPM_WORKFORCE_BOOTSTRAP_MODE", "qualification");
  vi.stubEnv("PAYPM_WORKFORCE_BOOTSTRAP_INVITED_USER_IDS", "12345");
  vi.stubEnv("PAYPM_WORKFORCE_FLOW_KEY_BASE64", Buffer.alloc(32, 6).toString("base64"));
  vi.mocked(getAuthRequest).mockResolvedValue({ authRequest: { clientId: "workforce-client" } } as any);
  vi.mocked(listUsers).mockResolvedValue({ result: [user] } as any);
  vi.mocked(getLoginSettings).mockResolvedValue({ allowLocalAuthentication: true } as any);
  vi.mocked(listAuthenticationMethodTypes).mockResolvedValue({
    authMethodTypes: [AuthenticationMethodType.OTP_EMAIL],
  } as any);
  vi.mocked(createSessionAndUpdateCookie).mockResolvedValue({
    session: session(),
    sessionCookie: { token: "must-not-return" },
    challenges: { otpEmail: "must-not-return" },
  } as any);
});
afterEach(() => vi.unstubAllEnvs());

describe("headless workforce email-primary flow", () => {
  it("keeps readiness disabled until the owning privilege gates are qualified", async () => {
    vi.stubEnv("PAYPM_WORKFORCE_EMAIL_OTP_READY", "false");
    expect(await startWorkforceEmailOtp({ email: "staff@example.com", requestId: "oidc_request" })).toHaveProperty("error");
    expect(createSessionAndUpdateCookie).not.toHaveBeenCalled();
  });
  it("sends provider email code only for an invited, verified and already enrolled exact staff user", async () => {
    const result = await startWorkforceEmailOtp({ email: " Staff@Example.com ", requestId: "oidc_request" });
    expect(result).toMatchObject({ sessionId: "provider-session", authenticationClass: "workforce_limited" });
    expect(JSON.stringify(result)).not.toContain("must-not-return");
    expect(vi.mocked(createSessionAndUpdateCookie).mock.calls[0][0].challenges?.otpEmail?.deliveryType.case).toBe(
      "sendCode",
    );
    expect(writeWorkforceState).toHaveBeenCalledWith(
      expect.objectContaining({ userId: "12345", clientId: "workforce-client", requestId: "oidc_request" }),
    );
  });
  it.each(["unregistered-client", "unenrolled", "no-policy", "ambiguous-email", "unapproved", "no-signing-key"])(
    "denies %s before delivery",
    async (kind) => {
      if (kind === "unregistered-client")
        vi.mocked(getAuthRequest).mockResolvedValue({ authRequest: { clientId: "commercial-client" } } as any);
      if (kind === "unenrolled") vi.mocked(listAuthenticationMethodTypes).mockResolvedValue({ authMethodTypes: [] } as any);
      if (kind === "no-policy") vi.mocked(getLoginSettings).mockResolvedValue(undefined);
      if (kind === "ambiguous-email") vi.mocked(listUsers).mockResolvedValue({ result: [user, user] } as any);
      if (kind === "unapproved") vi.stubEnv("PAYPM_WORKFORCE_BOOTSTRAP_INVITED_USER_IDS", "99999");
      if (kind === "no-signing-key") vi.stubEnv("PAYPM_WORKFORCE_FLOW_KEY_BASE64", "");
      expect(await startWorkforceEmailOtp({ email: "staff@example.com", requestId: "oidc_request" })).toHaveProperty(
        "error",
      );
      expect(createSessionAndUpdateCookie).not.toHaveBeenCalled();
    },
  );
  it("forwards exact code to the provider and admits only accepted fresh email evidence", async () => {
    vi.mocked(readWorkforceState).mockResolvedValue({
      purpose: "email-challenge",
      sessionId: "provider-session",
      userId: "12345",
      clientId: "workforce-client",
      requestId: "oidc_request",
      issuedAt: Date.now() - 2000,
      expiresAt: Date.now() + 298000,
    });
    vi.mocked(getSessionCookieById).mockResolvedValue({
      id: "provider-session",
      token: "provider-token",
      requestId: "oidc_request",
    } as any);
    vi.mocked(getSession).mockResolvedValue({ session: session() } as any);
    vi.mocked(getUserByID).mockResolvedValue({ user } as any);
    const accepted = session();
    accepted.factors.otpEmail = { verifiedAt: timestamp(0) };
    vi.mocked(setSessionAndUpdateCookie).mockResolvedValue(accepted);
    vi.mocked(completeFlowOrGetUrl).mockResolvedValue({ redirect: "https://app.example.com/callback" });
    expect(
      await verifyWorkforceEmailOtp({ sessionId: "provider-session", requestId: "oidc_request", code: "123456" }),
    ).toHaveProperty("redirect");
    expect(vi.mocked(setSessionAndUpdateCookie).mock.calls[0][0].checks?.otpEmail?.code).toBe("123456");
    expect(writeWorkforceState).toHaveBeenCalledWith(expect.objectContaining({ purpose: "limited-admission" }));
    accepted.factors.otpEmail.verifiedAt = timestamp(-600000);
    expect(
      await verifyWorkforceEmailOtp({ sessionId: "provider-session", requestId: "oidc_request", code: "123456" }),
    ).toHaveProperty("error");
  });
  it("denies a swapped request/session binding before provider verification", async () => {
    vi.mocked(readWorkforceState).mockResolvedValue({
      purpose: "email-challenge",
      sessionId: "different-session",
      userId: "12345",
      clientId: "workforce-client",
      requestId: "oidc_request",
      issuedAt: Date.now() - 2000,
      expiresAt: Date.now() + 298000,
    });
    expect(
      await verifyWorkforceEmailOtp({ sessionId: "provider-session", requestId: "oidc_request", code: "123456" }),
    ).toHaveProperty("error");
    expect(setSessionAndUpdateCookie).not.toHaveBeenCalled();
  });
});
