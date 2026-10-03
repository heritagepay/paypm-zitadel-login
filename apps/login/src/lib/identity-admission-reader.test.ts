import { UserState } from "@zitadel/proto/zitadel/user/v2/user_pb";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { readIdentityAdmission } from "./identity-admission-reader";
import { verifyWorkforceOidcProof } from "./operations-oidc-proof";
import { identityWorkforceEligibility } from "./workforce-policy";
import { workforceProvider } from "./workforce-provider";
import { workforceStore } from "./workforce-store";
import { getUserByID } from "./zitadel";
vi.mock("next/headers", () => ({ headers: vi.fn(() => new Headers()) }));
vi.mock("./service-url", () => ({ getServiceConfig: () => ({ serviceConfig: { baseUrl: "https://auth.paypm.test" } }) }));
vi.mock("./operations-oidc-proof", () => ({ verifyWorkforceOidcProof: vi.fn() }));
vi.mock("./workforce-store", () => ({ workforceStore: vi.fn() }));
vi.mock("./workforce-provider", () => ({ workforceProvider: vi.fn() }));
vi.mock("./zitadel", () => ({ getUserByID: vi.fn() }));
vi.mock("./workforce-policy", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./workforce-policy")>()),
  identityWorkforceEligibility: { resolve: vi.fn() },
}));
const secret = Buffer.alloc(32, 14).toString("base64url"),
  personId = "ad067362-c41b-4c15-8645-64be64eebf9c";
const proof = {
  issuer: "https://auth.paypm.test",
  providerSubject: "700",
  baseSessionId: "900",
  clientId: "identity@paypm",
  tokenId: "v2_distinct:access",
  idTokenHash: "1".repeat(64),
  accessTokenHash: "2".repeat(64),
  nonceHash: "3".repeat(64),
};
const policy = {
  clientId: proof.clientId,
  appId: "identity-administration",
  deploymentId: "heritagepay",
  environment: "sandbox",
};
const input = {
  idToken: "synthetic-signed",
  accessToken: "synthetic-access",
  nonce: "4".repeat(43),
  clientId: proof.clientId,
};
const call = (body: any = input, token = secret) =>
  readIdentityAdmission(
    new Request("https://login.paypm.test/api/internal/v1/identity/admissions/check", {
      method: "POST",
      headers: { authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    }),
  );
let store: any, provider: any, admission: any;
beforeEach(() => {
  vi.resetAllMocks();
  vi.stubEnv("PAYPM_WORKFORCE_ORGANIZATION_ID", "300");
  vi.stubEnv("PAYPM_WORKFORCE_ISSUER", proof.issuer);
  vi.stubEnv("PAYPM_WORKFORCE_OIDC_CLIENT_IDS", proof.clientId);
  vi.stubEnv("PAYPM_WORKFORCE_EMAIL_OTP_READY", "true");
  vi.stubEnv(
    "PAYPM_WORKFORCE_OIDC_ADMISSION_POLICIES_JSON",
    JSON.stringify([{ clientId: proof.clientId, mode: "limited" }]),
  );
  vi.stubEnv("PAYPM_IDENTITY_OIDC_CLIENT_POLICIES_JSON", JSON.stringify([policy]));
  vi.stubEnv("PAYPM_IDENTITY_ADMISSION_READER_TOKEN", secret);
  vi.stubEnv("PAYPM_OPERATIONS_ADMISSION_READER_TOKEN", Buffer.alloc(32, 29).toString("base64url"));
  vi.stubEnv("PAYPM_WORKFORCE_ADMISSION_READER_TOKEN", Buffer.alloc(32, 15).toString("base64url"));
  vi.mocked(verifyWorkforceOidcProof).mockResolvedValue(proof);
  const n = Date.now() - 1000,
    ts = (off: number) => ({ seconds: BigInt(Math.floor((n + off) / 1000)), nanos: ((n + off) % 1000) * 1000000 });
  admission = {
    request_id: "oidc_owned",
    challenge_id: personId,
    epoch: "2",
    verified_at: new Date(n),
    absolute_expires_at: new Date(n + 28800000),
  };
  store = { currentAdmission: vi.fn(async () => admission), challenge: vi.fn(), admission: vi.fn(async () => true) };
  provider = {
    read: vi.fn(async () => ({
      id: "900",
      creationDate: ts(-5000),
      expirationDate: ts(28800000),
      factors: { user: { id: "700", organizationId: "300" }, otpEmail: { verifiedAt: ts(0) } },
    })),
  };
  vi.mocked(workforceStore).mockReturnValue(store);
  vi.mocked(workforceProvider).mockResolvedValue(provider);
  vi.mocked(getUserByID).mockResolvedValue({
    user: {
      state: UserState.ACTIVE,
      type: { case: "human", value: { email: { isVerified: true } } },
      details: { resourceOwner: "300" },
    },
  } as any);
  vi.mocked(identityWorkforceEligibility.resolve).mockResolvedValue({ personId, organizationId: "300", eligible: true });
});
afterEach(() => vi.unstubAllEnvs());
describe("separate Identity current admission boundary", () => {
  it.each([
    "PAYPM_IDENTITY_ACTION_BFF_TOKEN",
    "PAYPM_IDENTITY_ACTION_CONSUMER_TOKEN",
    "PAYPM_IDENTITY_INTROSPECTION_CLIENT_SECRET",
    "PAYPM_IDENTITY_LOGOUT_TOKEN",
    "PAYPM_OPERATIONS_ADMISSION_READER_TOKEN",
    "PAYPM_OPERATIONS_ACTION_BFF_TOKEN",
    "PAYPM_OPERATIONS_GRANT_CONSUMER_TOKEN",
    "PAYPM_OPERATIONS_DEPLOYMENT_GRANT_BFF_TOKEN",
    "PAYPM_OPERATIONS_DEPLOYMENT_GRANT_CONSUMER_TOKEN",
    "PAYPM_OPERATIONS_DEPLOYMENT_GRANT_AUTHORITY_API_KEY",
    "PAYPM_OPERATIONS_KYC_GRANT_BFF_TOKEN",
    "PAYPM_OPERATIONS_KYC_GRANT_CONSUMER_TOKEN",
    "PAYPM_OPERATIONS_KYC_GRANT_AUTHORITY_API_KEY",
    "PAYPM_OPERATIONS_LOGOUT_TOKEN",
  ])("denies %s secret reuse before validating actor proofs", async (name) => {
    vi.stubEnv(name, process.env.PAYPM_IDENTITY_ADMISSION_READER_TOKEN!);
    expect((await call()).status).toBe(403);
    expect(verifyWorkforceOidcProof).not.toHaveBeenCalled();
  });
  it("returns the exact 22-field tuple with canonical Person and no product grants", async () => {
    const response = await call();
    expect(response.status).toBe(200);
    const result = await response.json();
    expect(Object.keys(result)).toHaveLength(22);
    expect(result).toEqual({
      active: true,
      ...proof,
      personId,
      plane: "workforce",
      ...policy,
      contextId: "300",
      requestId: "oidc_owned",
      challengeId: personId,
      authenticationClass: "workforce_limited",
      verifiedAt: admission.verified_at.toISOString(),
      absoluteExpiresAt: admission.absolute_expires_at.toISOString(),
      checkedAt: expect.any(String),
      revocationVersion: "2",
    });
    expect(store.admission).toHaveBeenCalledWith("900", "700", proof.clientId, "oidc_owned");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("X-PayPM-Operations-Retirement-Proof")).toBeNull();
    expect(verifyWorkforceOidcProof).toHaveBeenCalledWith(input, proof.issuer, "identity");
  });
  it.each([
    "wrong-purpose",
    "reused-secret",
    "missing-policy",
    "duplicate-policy",
    "unknown-client",
    "actor-header",
    "signature",
    "revoked",
    "late-logout",
    "epoch-change",
    "other-session",
    "other-provider-person",
    "factor-time",
    "disabled",
    "workforce-invitation-revoked",
    "other-Person-organization",
    "provider-outage",
  ])("denies %s without creating Identity authority", async (kind) => {
    if (kind === "reused-secret")
      vi.stubEnv("PAYPM_IDENTITY_ADMISSION_READER_TOKEN", process.env.PAYPM_WORKFORCE_ADMISSION_READER_TOKEN!);
    if (kind === "missing-policy") vi.stubEnv("PAYPM_IDENTITY_OIDC_CLIENT_POLICIES_JSON", "[]");
    if (kind === "duplicate-policy")
      vi.stubEnv("PAYPM_IDENTITY_OIDC_CLIENT_POLICIES_JSON", JSON.stringify([policy, policy]));
    if (kind === "signature") vi.mocked(verifyWorkforceOidcProof).mockRejectedValue(new Error("invalid"));
    if (kind === "revoked") store.currentAdmission.mockResolvedValue(undefined);
    if (kind === "late-logout") store.admission.mockResolvedValue(false);
    if (kind === "epoch-change")
      store.currentAdmission.mockResolvedValueOnce(admission).mockResolvedValue({ ...admission, epoch: "3" });
    if (kind === "other-session" || kind === "other-provider-person" || kind === "factor-time") {
      const session = await provider.read();
      if (kind === "other-session") session.id = "901";
      if (kind === "other-provider-person") session.factors.user.id = "701";
      if (kind === "factor-time") session.factors.otpEmail.verifiedAt.nanos += 1000000;
      provider.read.mockResolvedValue(session);
    }
    if (kind === "disabled") vi.mocked(getUserByID).mockResolvedValue({ user: { state: UserState.INACTIVE } } as any);
    if (kind === "workforce-invitation-revoked")
      vi.mocked(identityWorkforceEligibility.resolve).mockResolvedValue({
        personId,
        organizationId: "300",
        eligible: false,
      });
    if (kind === "other-Person-organization")
      vi.mocked(identityWorkforceEligibility.resolve).mockResolvedValue({ personId, organizationId: "301", eligible: true });
    if (kind === "provider-outage") provider.read.mockRejectedValue(new Error("unavailable"));
    const body =
      kind === "actor-header" ? { ...input, personId } : kind === "unknown-client" ? { ...input, clientId: "other" } : input;
    const response = await call(
      body,
      kind === "wrong-purpose" ? process.env.PAYPM_WORKFORCE_ADMISSION_READER_TOKEN : secret,
    );
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ active: false });
  });
});
