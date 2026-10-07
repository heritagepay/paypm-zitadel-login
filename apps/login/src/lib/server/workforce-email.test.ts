import { UserState } from "@zitadel/proto/zitadel/user/v2/user_pb";
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { randomUUID } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { completeFlowOrGetUrl } from "../client";
import { addSessionToCookie, getSessionCookieById, removeSessionFromCookie } from "../cookies";
import { WorkforceProvider, workforceProvider } from "../workforce-provider";
import { deleteWorkforceState, readWorkforceState, writeWorkforceState } from "../workforce-state";
import { workforceStore, WorkforceStoreError, type WorkforceAttempt, type WorkforceChallenge } from "../workforce-store";
import {
  getAuthRequest,
  getLoginSettings,
  getSession,
  getUserByID,
  listAuthenticationMethodTypes,
  listUsers,
} from "../zitadel";
import {
  cancelWorkforceEmailOtp,
  resendWorkforceEmailOtp,
  startWorkforceEmailOtp,
  verifyWorkforceEmailOtp,
} from "./workforce-email";
vi.mock("next/headers", () => ({ headers: vi.fn(() => new Headers()) }));
vi.mock("../service-url", () => ({ getServiceConfig: () => ({ serviceConfig: { baseUrl: "https://auth.example.com" } }) }));
vi.mock("../zitadel", () => ({
  getAuthRequest: vi.fn(),
  getLoginSettings: vi.fn(),
  getUserByID: vi.fn(),
  listAuthenticationMethodTypes: vi.fn(),
  listUsers: vi.fn(),
  getSession: vi.fn(),
}));
vi.mock("../cookies", () => ({
  getSessionCookieById: vi.fn(),
  addSessionToCookie: vi.fn(),
  removeSessionFromCookie: vi.fn(),
}));
vi.mock("../workforce-state", async (original) => ({
  ...(await original<typeof import("../workforce-state")>()),
  readWorkforceState: vi.fn(),
  writeWorkforceState: vi.fn(),
  deleteWorkforceState: vi.fn(),
}));
vi.mock("../workforce-store", async (original) => ({
  ...(await original<typeof import("../workforce-store")>()),
  workforceStore: vi.fn(),
}));
vi.mock("../workforce-provider", async (original) => ({
  ...(await original<typeof import("../workforce-provider")>()),
  workforceProvider: vi.fn(),
}));
vi.mock("../client", () => ({ completeFlowOrGetUrl: vi.fn() }));
vi.mock("../fingerprint", () => ({ getUserAgent: vi.fn(() => ({})) }));
const ts = (offset: number) => {
  const n = Date.now() + offset;
  return { seconds: BigInt(Math.floor(n / 1000)), nanos: (n % 1000) * 1000000 };
};
const user = {
  userId: "12345",
  state: UserState.ACTIVE,
  details: { resourceOwner: "54321" },
  type: { case: "human", value: { email: { email: "staff@example.com", isVerified: true } } },
} as any;
let row: WorkforceChallenge, attempt: WorkforceAttempt, current: any, store: any, api: any;
const command = () => ({ email: "staff@example.com", requestId: "oidc_request", operationKey: randomUUID() });
const verify = () => ({
  sessionId: "provider-session",
  requestId: "oidc_request",
  operationKey: randomUUID(),
  code: "12345678",
});
beforeEach(() => {
  vi.resetAllMocks();
  for (const [key, value] of Object.entries({
    PAYPM_WORKFORCE_ORGANIZATION_ID: "54321",
    PAYPM_WORKFORCE_ISSUER: "https://auth.example.com",
    PAYPM_WORKFORCE_OIDC_CLIENT_IDS: "workforce-client",
    PAYPM_WORKFORCE_OIDC_ADMISSION_POLICIES_JSON: JSON.stringify([{ clientId: "workforce-client", mode: "limited" }]),
    PAYPM_WORKFORCE_EMAIL_OTP_READY: "true",
    PAYPM_WORKFORCE_BOOTSTRAP_MODE: "qualification",
    PAYPM_WORKFORCE_BOOTSTRAP_INVITED_USER_IDS: "12345",
    PAYPM_WORKFORCE_FLOW_KEY_BASE64: Buffer.alloc(32, 6).toString("base64"),
  }))
    vi.stubEnv(key, value);
  row = {
    id: randomUUID(),
    operation_key: randomUUID(),
    issuer: "https://auth.example.com",
    provider_subject: "12345",
    client_id: "workforce-client",
    request_id: "oidc_request",
    contact_hash: "a".repeat(64),
    request_hash: "b".repeat(64),
    epoch: "0",
    state: "session_pending",
    provider_session_id: null,
    provider_token_sealed: null,
    created_at: new Date(Date.now() - 2000),
    expires_at: new Date(Date.now() + 298000),
    issued_at: null,
    verified_at: null,
  };
  attempt = {
    id: randomUUID(),
    operation_key: randomUUID(),
    challenge_id: row.id,
    code_hash: "c".repeat(64),
    state: "pending",
    created_at: new Date(Date.now() - 500),
    completed_at: null,
  };
  current = {
    id: "provider-session",
    creationDate: ts(-1000),
    expirationDate: ts(28000000),
    metadata: { paypm_workforce_challenge: new TextEncoder().encode(row.id) },
    factors: { user: { id: "12345", organizationId: "54321", loginName: "staff@example.com", verifiedAt: ts(-900) } },
  };
  api = {
    createSession: vi.fn(async () => ({ sessionId: current.id, sessionToken: "must-not-return" })),
    getSession: vi.fn(async () => ({ session: current })),
    listSessions: vi.fn(async () => ({ sessions: [current], details: { totalResult: 1n } })),
    setSession: vi.fn(async (input: any) => {
      Object.assign(current.metadata, input.metadata);
      if (input.checks?.otpEmail) current.factors.otpEmail = { verifiedAt: ts(0) };
      return { sessionToken: "must-not-return" };
    }),
    deleteSession: vi.fn(),
  };
  store = {
    reserve: vi.fn(async () => row),
    pendingRevocations: vi.fn(async () => []),
    revocationCompleted: vi.fn(),
    claimSession: vi.fn(async () => true),
    claimDelivery: vi.fn(async () => true),
    orphanedSession: vi.fn(),
    session: vi.fn(async (_id: string, id: string) => {
      row.provider_session_id = id;
      if (row.state === "session_pending") row.state = "delivery_pending";
      return row;
    }),
    issued: vi.fn(async () => {
      row.state = "issued";
      row.issued_at = new Date(Date.now() - 200);
      return row;
    }),
    token: vi.fn(() => "must-not-return"),
    challenge: vi.fn(async () => row),
    challengeBySession: vi.fn(),
    cancelChallenge: vi.fn(),
    challengeForRequest: vi.fn(async () => row),
    attempt: vi.fn(async () => ({ ...attempt, first: true })),
    failed: vi.fn(),
    verified: vi.fn(async () => {
      row.state = "verified";
      return row;
    }),
    admission: vi.fn(async () => true),
  };
  vi.mocked(workforceStore).mockReturnValue(store);
  vi.mocked(workforceProvider).mockResolvedValue(new WorkforceProvider(api, "54321"));
  vi.mocked(getAuthRequest).mockResolvedValue({ authRequest: { clientId: "workforce-client" } } as any);
  vi.mocked(getSession).mockResolvedValue({ session: current } as any);
  vi.mocked(listUsers).mockResolvedValue({ result: [user] } as any);
  vi.mocked(getUserByID).mockResolvedValue({ user } as any);
  vi.mocked(getLoginSettings).mockResolvedValue({ allowLocalAuthentication: true } as any);
  vi.mocked(listAuthenticationMethodTypes).mockResolvedValue({
    authMethodTypes: [AuthenticationMethodType.OTP_EMAIL],
  } as any);
  vi.mocked(getSessionCookieById).mockResolvedValue({
    id: current.id,
    token: "must-not-return",
    requestId: row.request_id,
  } as any);
  vi.mocked(completeFlowOrGetUrl).mockResolvedValue({ redirect: "https://app.example.com/callback" });
});
afterEach(() => vi.unstubAllEnvs());
async function issued() {
  await startWorkforceEmailOtp(command());
  vi.mocked(readWorkforceState).mockResolvedValue({
    purpose: "email-challenge",
    challengeId: row.id,
    sessionId: current.id,
    userId: row.provider_subject,
    clientId: row.client_id,
    requestId: row.request_id,
    issuedAt: row.created_at.getTime(),
    expiresAt: row.expires_at.getTime(),
  });
}
describe("provider-owned workforce email OTP with durable orchestration", () => {
  it.each([
    "not-ready",
    "no-client-policy",
    "no-invite",
    "ambiguous",
    "no-provider-policy",
    "unenrolled",
    "no-signing-key",
    "quota-denied",
  ])("denies %s before any provider write", async (kind) => {
    if (kind === "not-ready") vi.stubEnv("PAYPM_WORKFORCE_EMAIL_OTP_READY", "false");
    if (kind === "no-client-policy") vi.stubEnv("PAYPM_WORKFORCE_OIDC_ADMISSION_POLICIES_JSON", "");
    if (kind === "no-invite") vi.stubEnv("PAYPM_WORKFORCE_BOOTSTRAP_INVITED_USER_IDS", "99999");
    if (kind === "ambiguous") vi.mocked(listUsers).mockResolvedValue({ result: [user, user] } as any);
    if (kind === "no-provider-policy") vi.mocked(getLoginSettings).mockResolvedValue(undefined);
    if (kind === "unenrolled") vi.mocked(listAuthenticationMethodTypes).mockResolvedValue({ authMethodTypes: [] } as any);
    if (kind === "no-signing-key") vi.stubEnv("PAYPM_WORKFORCE_FLOW_KEY_BASE64", "");
    if (kind === "quota-denied") store.reserve.mockRejectedValue(new WorkforceStoreError("workforce_delivery_rate_limited"));
    expect(await startWorkforceEmailOtp(command())).toHaveProperty("error");
    expect(api.createSession).not.toHaveBeenCalled();
    expect(api.setSession).not.toHaveBeenCalled();
  });
  it("reserves before provider issuance and returns only bounded public flow data", async () => {
    const result = await startWorkforceEmailOtp({ ...command(), email: " Staff@Example.com " });
    expect(result).toMatchObject({ sessionId: current.id, challengeId: row.id, authenticationClass: "workforce_limited" });
    expect(store.reserve.mock.invocationCallOrder[0]).toBeLessThan(api.createSession.mock.invocationCallOrder[0]);
    expect(JSON.stringify(result)).not.toContain("must-not-return");
    expect(api.setSession.mock.calls[0][0].challenges.otpEmail.deliveryType.case).toBe("sendCode");
    expect(writeWorkforceState).toHaveBeenCalledWith(expect.objectContaining({ challengeId: row.id }));
  });
  it("reads back an uncertain create instead of creating another provider session", async () => {
    const input = command();
    api.createSession.mockRejectedValueOnce(new Error("lost response"));
    store.claimSession.mockResolvedValueOnce(true).mockResolvedValue(false);
    expect(await startWorkforceEmailOtp(input)).toHaveProperty("error");
    expect(await startWorkforceEmailOtp(input)).toHaveProperty("sessionId");
    expect(api.createSession).toHaveBeenCalledTimes(1);
    expect(api.listSessions).toHaveBeenCalledTimes(1);
  });
  it("reads back flow-bound delivery metadata instead of resending after an uncertain delivery", async () => {
    const input = command(),
      apply = api.setSession.getMockImplementation();
    api.setSession.mockImplementationOnce(async (data: any) => {
      await apply!(data);
      throw new Error("lost send result");
    });
    store.claimDelivery.mockResolvedValueOnce(true).mockResolvedValue(false);
    expect(await startWorkforceEmailOtp(input)).toHaveProperty("error");
    expect(await startWorkforceEmailOtp(input)).toHaveProperty("sessionId");
    expect(api.setSession.mock.calls.filter(([data]: any) => data.challenges?.otpEmail)).toHaveLength(1);
  });
  it("reserves code attempt before provider verification and admits only current accepted exact factors", async () => {
    await issued();
    const result = await verifyWorkforceEmailOtp(verify());
    expect(result).toHaveProperty("redirect");
    const checks = api.setSession.mock.calls.find(([data]: any) => data.checks?.otpEmail);
    expect(checks[0].checks.otpEmail.code).toBe("12345678");
    expect(store.attempt.mock.invocationCallOrder[0]).toBeLessThan(api.setSession.mock.invocationCallOrder[1]);
    expect(store.verified).toHaveBeenCalled();
    expect(addSessionToCookie).toHaveBeenCalled();
    expect(writeWorkforceState).toHaveBeenCalledWith(
      expect.objectContaining({ purpose: "limited-admission", challengeId: row.id, issuedAt: row.created_at.getTime() }),
    );
  });
  it("uses the accepted immutable attempt marker to recover a lost verification response without repeating the code", async () => {
    await issued();
    const apply = api.setSession.getMockImplementation();
    api.setSession.mockImplementationOnce(async (data: any) => {
      await apply!(data);
      throw new Error("lost verification result");
    });
    expect(await verifyWorkforceEmailOtp(verify())).toHaveProperty("redirect");
    expect(api.setSession.mock.calls.filter(([data]: any) => data.checks?.otpEmail)).toHaveLength(1);
  });
  it.each(["wrong-request", "stale-factor", "missing-factor", "late-logout", "attempt-exhausted"])(
    "denies %s before callback admission",
    async (kind) => {
      await issued();
      if (kind === "wrong-request") vi.mocked(readWorkforceState).mockResolvedValue(undefined);
      if (kind === "stale-factor" || kind === "missing-factor") {
        const apply = api.setSession.getMockImplementation();
        api.setSession.mockImplementation(async (data: any) => {
          const r = await apply!(data);
          if (data.checks?.otpEmail)
            current.factors.otpEmail = kind === "stale-factor" ? { verifiedAt: ts(-600000) } : undefined;
          return r;
        });
      }
      if (kind === "late-logout") store.admission.mockResolvedValue(false);
      if (kind === "attempt-exhausted")
        store.attempt.mockRejectedValue(new WorkforceStoreError("workforce_attempts_exhausted"));
      expect(await verifyWorkforceEmailOtp(verify())).toHaveProperty("error");
      expect(completeFlowOrGetUrl).not.toHaveBeenCalled();
    },
  );
  it("queues any unadmitted provider session created after logout for deletion", async () => {
    store.session.mockRejectedValue(new WorkforceStoreError("challenge_not_active"));
    expect(await startWorkforceEmailOtp(command())).toHaveProperty("error");
    expect(store.orphanedSession).toHaveBeenCalledWith(row.id, current.id);
  });
  it("resend rechecks enrolled OTP method before retiring the prior challenge", async () => {
    await issued();
    store.reserve.mockClear();
    vi.mocked(listAuthenticationMethodTypes).mockResolvedValue({ authMethodTypes: [] } as any);
    expect(
      await resendWorkforceEmailOtp({ sessionId: current.id, requestId: row.request_id, operationKey: randomUUID() }),
    ).toHaveProperty("error");
    expect(store.reserve).not.toHaveBeenCalled();
  });
  it("recovers a resend response lost after the signed cookie changed without changing the original operation", async () => {
    await issued();
    const previous = { ...row, id: randomUUID(), provider_session_id: "previous-provider", state: "retired" };
    store.challengeBySession.mockResolvedValue(previous);
    const op = randomUUID();
    expect(
      await resendWorkforceEmailOtp({ sessionId: "previous-provider", requestId: row.request_id, operationKey: op }),
    ).toHaveProperty("sessionId", current.id);
    expect(store.challengeBySession).toHaveBeenCalledWith({
      issuer: row.issuer,
      userId: row.provider_subject,
      clientId: row.client_id,
      requestId: row.request_id,
      sessionId: "previous-provider",
    });
    expect(store.reserve).toHaveBeenLastCalledWith(expect.objectContaining({ operationKey: op }), previous.id);
    expect(api.createSession).toHaveBeenCalledTimes(1);
  });
  it("hands a privileged client to an actual fresh passkey ceremony without completing its OTP callback", async () => {
    await issued();
    vi.stubEnv(
      "PAYPM_WORKFORCE_OIDC_ADMISSION_POLICIES_JSON",
      JSON.stringify([{ clientId: row.client_id, mode: "fresh_passkey" }]),
    );
    const result = await verifyWorkforceEmailOtp(verify());
    expect(result).toMatchObject({ redirect: expect.stringContaining("/passkey?") });
    expect(completeFlowOrGetUrl).not.toHaveBeenCalled();
    expect(store.verified).toHaveBeenCalled();
  });
  it("retires the exact signed challenge before cookie cleanup and tolerates a provider revocation outage", async () => {
    await issued();
    store.pendingRevocations.mockResolvedValue([{ provider_session_id: current.id }]);
    api.deleteSession.mockRejectedValue(new Error("provider unavailable"));
    expect(await cancelWorkforceEmailOtp({ requestId: row.request_id, sessionId: current.id })).toEqual({ cancelled: true });
    expect(store.cancelChallenge).toHaveBeenCalledWith(row.id);
    expect(store.cancelChallenge.mock.invocationCallOrder[0]).toBeLessThan(
      vi.mocked(removeSessionFromCookie).mock.invocationCallOrder[0],
    );
    expect(deleteWorkforceState).toHaveBeenCalled();
    expect(store.revocationCompleted).not.toHaveBeenCalled();
  });
  it("cannot cancel a challenge from another request or subject", async () => {
    await issued();
    expect(await cancelWorkforceEmailOtp({ requestId: "oidc_other", sessionId: current.id })).toHaveProperty("error");
    row.provider_subject = "different";
    expect(await cancelWorkforceEmailOtp({ requestId: row.request_id, sessionId: current.id })).toHaveProperty("error");
    expect(store.cancelChallenge).not.toHaveBeenCalled();
  });
  it("can retire an expired signed challenge only through a current exact provider session cookie", async () => {
    await issued();
    vi.mocked(readWorkforceState).mockResolvedValue(undefined);
    expect(await cancelWorkforceEmailOtp({ requestId: row.request_id, sessionId: current.id })).toEqual({ cancelled: true });
    expect(getSession).toHaveBeenCalledWith(
      expect.objectContaining({ sessionId: current.id, sessionToken: "must-not-return" }),
    );
    store.cancelChallenge.mockClear();
    vi.mocked(getSession).mockResolvedValue({
      session: { ...current, factors: { user: { id: "other", organizationId: "54321" } } },
    } as any);
    expect(await cancelWorkforceEmailOtp({ requestId: row.request_id, sessionId: current.id })).toHaveProperty("error");
    expect(store.cancelChallenge).not.toHaveBeenCalled();
  });
});

describe("native configured eight-digit email OTP", () => {
  it.each(["123456", "1234567", "123456789", "ABCDEFGH"])(
    "rejects wrong native code shape %s before provider verification",
    async (code) => {
      expect(await verifyWorkforceEmailOtp({ ...verify(), code })).toHaveProperty("error");
      expect(api.setSession).not.toHaveBeenCalled();
    },
  );
});
