// @vitest-environment node
import { UserState } from "@zitadel/proto/zitadel/user/v2/user_pb";
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { randomUUID } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { enrollmentIdentityRequest } from "../workforce-enrollment-identity-client";
import { workforceEnrollmentStore } from "../workforce-enrollment-store";
import { workforceProvider } from "../workforce-provider";
import { deleteWorkforceState, readWorkforceState, writeWorkforceState } from "../workforce-state";
import {
  addOTPEmail,
  getAuthRequest,
  getLoginSettings,
  getUserByID,
  listAuthenticationMethodTypes,
  verifyEmail,
} from "../zitadel";
import {
  cancelReviewedWorkforceEnrollment,
  completeReviewedWorkforceEnrollment,
  inspectReviewedWorkforceEnrollmentEntry,
  resendReviewedWorkforceEnrollment,
  reviewedWorkforceEmailVerificationTemplate,
  startReviewedWorkforceEnrollment,
  verifyReviewedWorkforceEnrollment,
  verifyReviewedWorkforceProfileEmail,
} from "./workforce-enrollment";
vi.mock("next/headers", () => ({ headers: vi.fn(async () => new Headers()) }));
vi.mock("../service-url", () => ({ getServiceConfig: () => ({ serviceConfig: { baseUrl: "https://auth.paypm.test" } }) }));
vi.mock("../zitadel", () => ({
  getAuthRequest: vi.fn(),
  getLoginSettings: vi.fn(),
  getUserByID: vi.fn(),
  listAuthenticationMethodTypes: vi.fn(),
  verifyEmail: vi.fn(),
  addOTPEmail: vi.fn(),
}));
vi.mock("../workforce-enrollment-identity-client", async (original) => ({
  ...(await original<typeof import("../workforce-enrollment-identity-client")>()),
  enrollmentIdentityRequest: vi.fn(),
}));
vi.mock("../workforce-enrollment-store", () => ({ workforceEnrollmentStore: vi.fn() }));
vi.mock("../workforce-provider", () => ({ workforceProvider: vi.fn() }));
vi.mock("../workforce-revocations", () => ({ flushWorkforceRevocations: vi.fn() }));
vi.mock("../workforce-state", () => ({
  readWorkforceState: vi.fn(),
  writeWorkforceState: vi.fn(),
  deleteWorkforceState: vi.fn(),
}));
const runtime = { sourceRevision: "a".repeat(40), imageDigest: "b".repeat(64), configurationSha256: "c".repeat(64) };
const ts = (ms: number) => ({ seconds: BigInt(Math.floor(ms / 1000)), nanos: (ms % 1000) * 1000000 });
let p: any, user: any, store: any, provider: any, row: any, flow: any, attempt: any, session: any, original: any;
const start = () => ({ operationId: p.enrollmentId, requestId: "oidc_owned", operationKey: randomUUID() });
const verify = () => ({ operationId: p.enrollmentId, challengeId: row.id, operationKey: randomUUID(), code: "12345678" });
beforeEach(() => {
  vi.resetAllMocks();
  for (const [k, v] of Object.entries({
    NEXT_PUBLIC_BASE_PATH: "/ui/v2/login",
    PAYPM_WORKFORCE_ISSUER: "https://auth.paypm.test",
    PAYPM_WORKFORCE_ORGANIZATION_ID: "300",
    PAYPM_WORKFORCE_OIDC_CLIENT_IDS: "staff-client",
    PAYPM_WORKFORCE_EMAIL_OTP_READY: "true",
    PAYPM_WORKFORCE_ENROLLMENT_RUNTIME_JSON: JSON.stringify(runtime),
  }))
    vi.stubEnv(k, v);
  const now = Date.now();
  p = {
    enrollmentId: randomUUID(),
    personId: randomUUID(),
    policyId: randomUUID(),
    issuer: "https://auth.paypm.test",
    organizationId: "300",
    clientId: "staff-client",
    providerSubject: "700",
    email: "staff@example.test",
    emailVerified: false,
    expiresAt: new Date(now + 120000).toISOString(),
    ...runtime,
    state: "qualified_enrollment",
  };
  user = {
    state: UserState.ACTIVE,
    details: { resourceOwner: "300" },
    type: { case: "human", value: { email: { email: p.email, isVerified: false } } },
  };
  row = {
    id: randomUUID(),
    purpose: "reviewed_enrollment",
    issuer: p.issuer,
    provider_subject: p.providerSubject,
    client_id: p.clientId,
    request_id: "oidc_owned",
    epoch: "0",
    provider_session_id: "800",
    state: "issued",
    created_at: new Date(now - 5000),
    expires_at: new Date(now + 120000),
  };
  flow = {
    purpose: "reviewed-workforce-enrollment",
    enrollmentId: p.enrollmentId,
    challengeId: row.id,
    sessionId: "800",
    userId: "700",
    clientId: "staff-client",
    requestId: "oidc_owned",
  };
  original = {
    enrollment_id: p.enrollmentId,
    provider_subject: p.providerSubject,
    client_id: p.clientId,
    request_id: "oidc_owned",
    created_at: new Date(now - 6000),
    expires_at: new Date(now + 120000),
  };
  attempt = { id: randomUUID(), first: true, state: "pending" };
  session = {
    id: "800",
    creationDate: ts(now - 5000),
    expirationDate: ts(now + 120000),
    factors: { otpEmail: { verifiedAt: ts(now - 1000) } },
  };
  provider = {
    verify: vi.fn(async () => ({ session, token: "never-client-token" })),
    read: vi.fn(async () => session),
    token: vi.fn(async () => ({ session, token: "never-client-token" })),
    verificationAccepted: vi.fn(() => true),
    attachEnrollment: vi.fn(),
    deliveryAccepted: vi.fn(() => true),
  };
  store = {
    base: {
      reserve: vi.fn(async () => row),
      currentEnrollmentChallenge: vi.fn(async () => row),
      attempt: vi.fn(async () => attempt),
      session: vi.fn(async () => row),
      verifiedEnrollment: vi.fn(),
      verified: vi.fn(),
      failed: vi.fn(),
    },
    begin: vi.fn(async () => original),
    original: vi.fn(async () => original),
    matches: vi.fn(),
    profileAttempt: vi.fn(async () => true),
    attach: vi.fn(async () => ({ expiresAt: p.expiresAt })),
    ceremony: vi.fn(async () => ({})),
    retire: vi.fn(),
  };
  vi.mocked(enrollmentIdentityRequest).mockImplementation(async (op) =>
    op === "current"
      ? { ...p }
      : ({
          enrollmentId: p.enrollmentId,
          personId: p.personId,
          policyId: p.policyId,
          clientId: p.clientId,
          issuer: p.issuer,
          organizationId: p.organizationId,
          evidenceId: row.id,
          providerSessionId: "800",
          subject: p.providerSubject,
          profileClass: "workforce",
          state: "completed",
        } as any),
  );
  vi.mocked(getAuthRequest).mockResolvedValue({ authRequest: { clientId: "staff-client" } } as any);
  vi.mocked(getUserByID).mockImplementation(async () => ({ user: structuredClone(user) }) as any);
  vi.mocked(getLoginSettings).mockResolvedValue({ allowLocalAuthentication: true } as any);
  vi.mocked(listAuthenticationMethodTypes).mockResolvedValue({
    authMethodTypes: [AuthenticationMethodType.OTP_EMAIL],
  } as any);
  vi.mocked(workforceEnrollmentStore).mockReturnValue(store);
  vi.mocked(workforceProvider).mockResolvedValue(provider);
  vi.mocked(readWorkforceState).mockImplementation(async () => flow);
});
afterEach(() => vi.unstubAllEnvs());
const verifiedProfile = () => {
  p.emailVerified = true;
  user.type.value.email.isVerified = true;
};
describe("reviewed workforce native ownership journey", () => {
  it("starts only server-approved named email, without session creation or normal admission", async () => {
    expect(await startReviewedWorkforceEnrollment(start())).toEqual({
      state: "profile_email_verification_pending",
      email: p.email,
    });
    expect(provider.verify).not.toHaveBeenCalled();
    expect(store.base.reserve).not.toHaveBeenCalled();
    expect(writeWorkforceState).toHaveBeenCalledWith(
      expect.objectContaining({
        purpose: "reviewed-workforce-enrollment",
        enrollmentId: p.enrollmentId,
        issuedAt: original.created_at.getTime(),
      }),
    );
  });
  it.each(["off", "wrong-client", "foreign-home", "unverified-mismatch"])(
    "denies %s before enrollment association",
    async (kind) => {
      if (kind === "off") vi.stubEnv("PAYPM_WORKFORCE_ENROLLMENT_RUNTIME_JSON", "");
      if (kind === "wrong-client")
        vi.mocked(getAuthRequest).mockResolvedValue({ authRequest: { clientId: "other" } } as any);
      if (kind === "foreign-home") user.details.resourceOwner = "301";
      if (kind === "unverified-mismatch") user.type.value.email.isVerified = true;
      expect(await startReviewedWorkforceEnrollment(start())).toHaveProperty("error");
      expect(store.begin).not.toHaveBeenCalled();
    },
  );
  it("consumes profile code then requires provider readback before enrolling OTP_EMAIL", async () => {
    vi.mocked(verifyEmail).mockImplementation(async () => {
      verifiedProfile();
      return {} as any;
    });
    vi.mocked(listAuthenticationMethodTypes)
      .mockResolvedValueOnce({ authMethodTypes: [] } as any)
      .mockResolvedValueOnce({ authMethodTypes: [AuthenticationMethodType.OTP_EMAIL] } as any);
    expect(
      await verifyReviewedWorkforceProfileEmail({ operationId: p.enrollmentId, operationKey: randomUUID(), code: "A7K9Q2" }),
    ).toEqual({ state: "profile_email_verified" });
    expect(verifyEmail).toHaveBeenCalledWith(expect.objectContaining({ userId: "700", verificationCode: "A7K9Q2" }));
    expect(addOTPEmail).toHaveBeenCalledOnce();
    expect(vi.mocked(verifyEmail).mock.invocationCallOrder[0]).toBeLessThan(
      vi.mocked(addOTPEmail).mock.invocationCallOrder[0],
    );
    expect(store.base.verified).not.toHaveBeenCalled();
  });
  it("resolves lost VerifyEmail response by exact readback, never blindly repeats same claimed code", async () => {
    vi.mocked(verifyEmail).mockImplementation(async () => {
      verifiedProfile();
      throw new Error("lost response");
    });
    const command = { operationId: p.enrollmentId, operationKey: randomUUID(), code: "A7K9Q2" };
    expect(await verifyReviewedWorkforceProfileEmail(command)).toHaveProperty("state", "profile_email_verified");
    expect(await verifyReviewedWorkforceProfileEmail(command)).toHaveProperty("state", "profile_email_verified");
    expect(verifyEmail).toHaveBeenCalledOnce();
  });
  it("failed native profile proof cannot enable OTP method or manually mark contact verified", async () => {
    vi.mocked(verifyEmail).mockRejectedValue(new Error("incorrect"));
    expect(
      await verifyReviewedWorkforceProfileEmail({ operationId: p.enrollmentId, operationKey: randomUUID(), code: "A7K9Q2" }),
    ).toHaveProperty("error");
    expect(addOTPEmail).not.toHaveBeenCalled();
  });
  it("accepts fresh eight-digit SessionOTP as link-pending only, never login admission", async () => {
    verifiedProfile();
    expect(await verifyReviewedWorkforceEnrollment(verify())).toEqual({ state: "identity_link_pending" });
    expect(provider.verify).toHaveBeenCalledWith(row, attempt, "12345678");
    expect(store.base.verifiedEnrollment).toHaveBeenCalledOnce();
    expect(store.base.verified).not.toHaveBeenCalled();
    expect(JSON.stringify(await verifyReviewedWorkforceEnrollment(verify()))).not.toContain("never-client-token");
  });
  it.each(["123456", "123456789", "ABCDEFGH"])(
    "denies wrong native OTP length/shape %s before native verify",
    async (code) => {
      verifiedProfile();
      expect(await verifyReviewedWorkforceEnrollment({ ...verify(), code })).toHaveProperty("error");
      expect(provider.verify).not.toHaveBeenCalled();
    },
  );
  it("retirement/logout race after accepted provider result cannot record completion", async () => {
    verifiedProfile();
    store.original.mockResolvedValueOnce(original).mockRejectedValueOnce(new Error("epoch retired"));
    expect(await verifyReviewedWorkforceEnrollment(verify())).toHaveProperty("error");
    expect(store.base.verifiedEnrollment).not.toHaveBeenCalled();
  });
  it("lost OTP response requires exact accepted native proof, not synthetic success", async () => {
    verifiedProfile();
    provider.verify.mockRejectedValue(new Error("lost"));
    provider.verificationAccepted.mockReturnValue(false);
    expect(await verifyReviewedWorkforceEnrollment(verify())).toHaveProperty("error");
    expect(store.base.verifiedEnrollment).not.toHaveBeenCalled();
  });
  it("completes exact existing Person link, remains access-pending and retires enrollment", async () => {
    verifiedProfile();
    expect(await completeReviewedWorkforceEnrollment(verify())).toEqual({ state: "enrollment_completed_access_pending" });
    expect(enrollmentIdentityRequest).toHaveBeenCalledWith("complete", p.enrollmentId, {
      challengeId: row.id,
      sessionId: "800",
    });
    expect(store.retire).toHaveBeenCalledWith(p.enrollmentId, "completed");
    expect(deleteWorkforceState).not.toHaveBeenCalled();
    expect(store.base.verified).not.toHaveBeenCalled();
  });
  it("wrong canonical result cannot complete or grant access", async () => {
    verifiedProfile();
    vi.mocked(enrollmentIdentityRequest).mockImplementation(async (op) =>
      op === "current" ? p : ({ enrollmentId: p.enrollmentId, personId: randomUUID() } as any),
    );
    expect(await completeReviewedWorkforceEnrollment(verify())).toHaveProperty("error");
    expect(store.retire).not.toHaveBeenCalled();
  });
  it("cancel uses existing owner revocation path and deletes only enrollment flow", async () => {
    expect(await cancelReviewedWorkforceEnrollment({ operationId: p.enrollmentId, operationKey: randomUUID() })).toEqual({
      state: "cancelled",
    });
    expect(store.retire).toHaveBeenCalledWith(p.enrollmentId, "cancelled");
    expect(deleteWorkforceState).toHaveBeenCalledOnce();
  });
  it("resend reserves same contact/purpose and retires exact previous challenge", async () => {
    verifiedProfile();
    expect(await resendReviewedWorkforceEnrollment(verify())).toHaveProperty("state", "otp_pending");
    expect(store.base.reserve).toHaveBeenCalledWith(
      expect.objectContaining({ contact: p.email, purpose: "reviewed_enrollment" }),
      row.id,
    );
  });
  it("native callback recipe carries bounded operation in query and code in fragment only", async () => {
    const url = await reviewedWorkforceEmailVerificationTemplate(p.enrollmentId, "oidc_owned");
    expect(url).toBe(
      `https://auth.paypm.test/ui/v2/login/workforce-enrollment?operationId=${p.enrollmentId}&requestId=oidc_owned#code={{.Code}}`,
    );
    expect(url.length).toBeLessThanOrEqual(200);
  });
});

describe("readonly original enrollment entry", () => {
  it("unbound mail view returns only approved email and missing OIDC fact, no effects", async () => {
    vi.mocked(readWorkforceState).mockResolvedValue(undefined);
    expect(await inspectReviewedWorkforceEnrollmentEntry({ operationId: p.enrollmentId })).toEqual({
      email: p.email,
      state: "oidc_request_required",
    });
    expect(writeWorkforceState).not.toHaveBeenCalled();
    expect(store.begin).not.toHaveBeenCalled();
    expect(store.base.reserve).not.toHaveBeenCalled();
    expect(provider.verify).not.toHaveBeenCalled();
    expect(getAuthRequest).not.toHaveBeenCalled();
  });
  it("actual matching native request may show explicit start, never silently sends OTP", async () => {
    vi.mocked(readWorkforceState).mockResolvedValue(undefined);
    expect(await inspectReviewedWorkforceEnrollmentEntry({ operationId: p.enrollmentId, requestId: "oidc_owned" })).toEqual({
      email: p.email,
      requestId: "oidc_owned",
      state: "ready_to_start",
    });
    expect(writeWorkforceState).not.toHaveBeenCalled();
    expect(store.begin).not.toHaveBeenCalled();
    expect(store.base.reserve).not.toHaveBeenCalled();
  });
  it("rejects forged client or changed signed original query", async () => {
    vi.mocked(getAuthRequest).mockResolvedValue({ authRequest: { clientId: "other" } } as any);
    expect(
      await inspectReviewedWorkforceEnrollmentEntry({ operationId: p.enrollmentId, requestId: "oidc_owned" }),
    ).toHaveProperty("error");
    vi.mocked(getAuthRequest).mockResolvedValue({ authRequest: { clientId: "staff-client" } } as any);
    expect(
      await inspectReviewedWorkforceEnrollmentEntry({ operationId: p.enrollmentId, requestId: "oidc_different" }),
    ).toHaveProperty("error");
    expect(writeWorkforceState).not.toHaveBeenCalled();
  });
  it("owned view derives email/timing from actual server context, no code or provider token", async () => {
    verifiedProfile();
    const result = await inspectReviewedWorkforceEnrollmentEntry({ operationId: p.enrollmentId });
    expect(result).toMatchObject({
      state: "otp_pending",
      email: p.email,
      requestId: "oidc_owned",
      challengeId: row.id,
      resendAt: new Date(row.created_at.getTime() + 60000).toISOString(),
    });
    expect(JSON.stringify(result)).not.toContain("never-client-token");
    expect(writeWorkforceState).not.toHaveBeenCalled();
    expect(store.base.reserve).not.toHaveBeenCalled();
  });
  it("final logout bookend cannot present stale owned challenge", async () => {
    store.original.mockResolvedValueOnce(original).mockRejectedValueOnce(new Error("retired"));
    expect(await inspectReviewedWorkforceEnrollmentEntry({ operationId: p.enrollmentId })).toHaveProperty("error");
    expect(writeWorkforceState).not.toHaveBeenCalled();
  });
  it("native template validates actual request/client without assuming future user exists", async () => {
    vi.mocked(getUserByID).mockRejectedValue(new Error("not created"));
    expect(await reviewedWorkforceEmailVerificationTemplate(p.enrollmentId, "oidc_owned")).toContain(
      "requestId=oidc_owned#code={{.Code}}",
    );
    expect(getUserByID).not.toHaveBeenCalled();
    vi.mocked(getAuthRequest).mockResolvedValue({ authRequest: { clientId: "other" } } as any);
    await expect(reviewedWorkforceEmailVerificationTemplate(p.enrollmentId, "oidc_owned")).rejects.toThrow("registered");
  });
  it.each([undefined, "", "/", "/ui/v2/login/", "/ui/v1/login", "https://auth.paypm.test/ui/v2/login", "ui/v2/login"])(
    "native template rejects unregistered base path %s before native lookup",
    async (basePath) => {
      vi.stubEnv("NEXT_PUBLIC_BASE_PATH", basePath);
      await expect(reviewedWorkforceEmailVerificationTemplate(p.enrollmentId, "oidc_owned")).rejects.toThrow("base path");
      expect(getAuthRequest).not.toHaveBeenCalled();
      expect(getUserByID).not.toHaveBeenCalled();
    },
  );
  it("native template preserves exact real request binding and bounded registered path", async () => {
    const value = await reviewedWorkforceEmailVerificationTemplate(p.enrollmentId, "oidc_owned");
    expect(getAuthRequest).toHaveBeenCalledWith({
      serviceConfig: { baseUrl: "https://auth.paypm.test" },
      authRequestId: "owned",
    });
    const url = new URL(value);
    expect(url.origin).toBe(p.issuer);
    expect(url.pathname).toBe("/ui/v2/login/workforce-enrollment");
    expect(url.searchParams.get("operationId")).toBe(p.enrollmentId);
    expect(url.searchParams.get("requestId")).toBe("oidc_owned");
    expect(url.searchParams.has("code")).toBe(false);
    expect(value.endsWith("#code={{.Code}}")).toBe(true);
    const exactLengthRequest = "oidc_" + "a".repeat(200 - value.length + "oidc_owned".length - 5);
    expect((await reviewedWorkforceEmailVerificationTemplate(p.enrollmentId, exactLengthRequest)).length).toBe(200);
    await expect(reviewedWorkforceEmailVerificationTemplate(p.enrollmentId, exactLengthRequest + "a")).rejects.toThrow(
      "bound",
    );
    vi.mocked(getAuthRequest).mockResolvedValue({} as any);
    await expect(reviewedWorkforceEmailVerificationTemplate(p.enrollmentId, "oidc_owned")).rejects.toThrow("registered");
  });
  it("native template rejects absent/invented shape and oversized final URL", async () => {
    await expect(reviewedWorkforceEmailVerificationTemplate(p.enrollmentId, undefined as any)).rejects.toThrow();
    await expect(reviewedWorkforceEmailVerificationTemplate(p.enrollmentId, "oidc_" + "a".repeat(200))).rejects.toThrow(
      "bound",
    );
  });
});

describe("truthful readonly delivery projection", () => {
  it("never presents accepted delivery before native issuance or after profile proof revoked", async () => {
    verifiedProfile();
    row.state = "delivery_pending";
    expect(await inspectReviewedWorkforceEnrollmentEntry({ operationId: p.enrollmentId })).toHaveProperty("error");
    row.state = "issued";
    p.emailVerified = false;
    user.type.value.email.isVerified = false;
    expect(await inspectReviewedWorkforceEnrollmentEntry({ operationId: p.enrollmentId })).toHaveProperty("error");
    expect(store.base.reserve).not.toHaveBeenCalled();
    expect(writeWorkforceState).not.toHaveBeenCalled();
  });
});
