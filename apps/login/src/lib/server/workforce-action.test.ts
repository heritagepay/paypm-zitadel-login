import { UserVerificationRequirement } from "@zitadel/proto/zitadel/session/v2/challenge_pb";
import { createHash } from "crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getSessionCookieById } from "../cookies";
import { deleteActionState, getActionState, storeActionState } from "../workforce-action-state";
import { workforceIdentityRequest } from "../workforce-identity-client";
import { workforceEligible } from "../workforce-policy";
import { readWorkforceState } from "../workforce-state";
import { createSessionFromChecksAndChallenges, getSession, getUserByID, setSession } from "../zitadel";
import { completeWorkforceAction, startWorkforceAction } from "./workforce-action";
vi.mock("next/headers", () => ({ headers: vi.fn(() => new Headers()) }));
vi.mock("../service-url", () => ({ getServiceConfig: () => ({ serviceConfig: { baseUrl: "https://auth.paypm.test" } }) }));
vi.mock("../zitadel", () => ({
  createSessionFromChecksAndChallenges: vi.fn(),
  getSession: vi.fn(),
  getUserByID: vi.fn(),
  setSession: vi.fn(),
}));
vi.mock("../cookies", () => ({ getSessionCookieById: vi.fn() }));
vi.mock("../workforce-state", () => ({ readWorkforceState: vi.fn() }));
vi.mock("../workforce-action-state", async (original) => ({
  ...(await original<typeof import("../workforce-action-state")>()),
  getActionState: vi.fn(),
  storeActionState: vi.fn(),
  deleteActionState: vi.fn(),
}));
vi.mock("../workforce-policy", async (original) => ({
  ...(await original<typeof import("../workforce-policy")>()),
  workforceEligible: vi.fn(),
}));
vi.mock("../workforce-identity-client", () => ({ workforceIdentityRequest: vi.fn() }));
const ts = (offset: number) => ({ seconds: BigInt(Math.floor((Date.now() + offset) / 1000)), nanos: 0 });
const challenge = Buffer.from("exact-provider-challenge-1234567").toString("base64url");
const requestId = "a200b513-7d03-45cb-bdd2-5d2c98d8765f";
const command = {
  action: "identity.recovery.review",
  payloadHash: "a".repeat(64),
  appId: "wallet_mobile",
  deploymentId: "heritagepay",
  environment: "production" as const,
};
const state = () => ({
  requestId,
  baseSessionId: "123",
  stepSessionId: "456",
  stepSessionToken: "must-not-return",
  userId: "700",
  clientId: "identity-client",
  challenge,
  issuedAt: Date.now() - 2000,
  expiresAt: Date.now() + 298000,
});
function assertion() {
  const auth = Buffer.alloc(37);
  createHash("sha256").update("login.paypm.test").digest().copy(auth);
  auth[32] = 5;
  return {
    id: "credential",
    rawId: "credential",
    type: "public-key",
    response: {
      clientDataJSON: Buffer.from(
        JSON.stringify({ type: "webauthn.get", challenge, origin: "https://login.paypm.test", crossOrigin: false }),
      ).toString("base64url"),
      authenticatorData: auth.toString("base64url"),
      signature: "provider-checks-signature",
      userHandle: null,
    },
  };
}
const base = () => ({
  id: "123",
  creationDate: ts(-10000),
  expirationDate: ts(28000000),
  factors: { user: { id: "700", organizationId: "300", verifiedAt: ts(-9000) }, otpEmail: { verifiedAt: ts(-8000) } },
});
beforeEach(() => {
  vi.resetAllMocks();
  vi.stubEnv("PAYPM_WORKFORCE_ORGANIZATION_ID", "300");
  vi.stubEnv("PAYPM_WORKFORCE_ISSUER", "https://auth.paypm.test");
  vi.stubEnv("PAYPM_WORKFORCE_OIDC_CLIENT_IDS", "identity-client");
  vi.stubEnv("PAYPM_WORKFORCE_FLOW_KEY_BASE64", Buffer.alloc(32, 6).toString("base64"));
  vi.stubEnv("PAYPM_WORKFORCE_PASSKEY_ORIGIN", "https://login.paypm.test");
  vi.stubEnv("PAYPM_WORKFORCE_PASSKEY_RP_ID", "login.paypm.test");
  vi.mocked(readWorkforceState).mockResolvedValue({
    purpose: "limited-admission",
    sessionId: "123",
    userId: "700",
    clientId: "identity-client",
    requestId: "oidc_request",
    issuedAt: Date.now() - 10000,
    expiresAt: Date.now() + 28000000,
  });
  vi.mocked(getSessionCookieById).mockResolvedValue({
    id: "123",
    token: "must-not-return",
    requestId: "oidc_request",
  } as any);
  vi.mocked(getSession).mockResolvedValue({ session: base() } as any);
  vi.mocked(getUserByID).mockResolvedValue({ user: { userId: "700" } } as any);
  vi.mocked(workforceEligible).mockResolvedValue(true);
  vi.mocked(createSessionFromChecksAndChallenges).mockResolvedValue({
    sessionId: "456",
    sessionToken: "must-not-return",
    challenges: {
      webAuthN: {
        publicKeyCredentialRequestOptions: {
          publicKey: { challenge, rpId: "login.paypm.test", userVerification: "required" },
        },
      },
    },
  } as any);
  vi.mocked(workforceIdentityRequest).mockResolvedValue({ requestId });
  vi.mocked(getActionState).mockResolvedValue(state());
});
afterEach(() => vi.unstubAllEnvs());
describe("fresh workforce action ceremony producer", () => {
  it("creates a separate provider challenge with required verification and persists exact scope without returning provider tokens", async () => {
    const result = await startWorkforceAction(command);
    expect(result).toMatchObject({ requestId, publicKey: { challenge, userVerification: "required" } });
    expect(JSON.stringify(result)).not.toContain("must-not-return");
    expect(createSessionFromChecksAndChallenges).toHaveBeenCalledWith(
      expect.objectContaining({
        checks: expect.objectContaining({ user: expect.objectContaining({ search: { case: "userId", value: "700" } }) }),
        challenges: expect.objectContaining({
          webAuthN: expect.objectContaining({
            domain: "login.paypm.test",
            userVerificationRequirement: UserVerificationRequirement.REQUIRED,
          }),
        }),
      }),
    );
    expect(workforceIdentityRequest).toHaveBeenCalledWith(
      "internal/v1/workforce-action-proofs/requests",
      expect.objectContaining({
        ...command,
        providerSubject: "700",
        baseSessionId: "123",
        stepSessionId: "456",
        clientId: "identity-client",
        contextId: "300",
        challenge,
      }),
    );
    expect(storeActionState).toHaveBeenCalled();
  });
  it.each(["no-policy", "no-admission", "revoked", "wrong-rp", "preferred-uv"])(
    "denies %s before accepting a proof",
    async (kind) => {
      if (kind === "no-policy") vi.stubEnv("PAYPM_WORKFORCE_PASSKEY_ORIGIN", "");
      if (kind === "no-admission") vi.mocked(readWorkforceState).mockResolvedValue(undefined);
      if (kind === "revoked") vi.mocked(workforceEligible).mockResolvedValue(false);
      if (kind === "wrong-rp" || kind === "preferred-uv")
        vi.mocked(createSessionFromChecksAndChallenges).mockResolvedValue({
          sessionId: "456",
          sessionToken: "private",
          challenges: {
            webAuthN: {
              publicKeyCredentialRequestOptions: {
                publicKey: {
                  challenge,
                  rpId: kind === "wrong-rp" ? "evil.test" : "login.paypm.test",
                  userVerification: "preferred",
                },
              },
            },
          },
        } as any);
      expect(await startWorkforceAction(command)).toHaveProperty("error");
      expect(storeActionState).not.toHaveBeenCalled();
    },
  );
  it("forwards the exact assertion and requires provider freshness before asking Identity for a one-use receipt", async () => {
    const signed = assertion();
    vi.mocked(setSession).mockResolvedValue({ sessionToken: "rotated-provider-token" } as any);
    vi.mocked(getSession)
      .mockResolvedValueOnce({ session: base() } as any)
      .mockResolvedValueOnce({
        session: {
          id: "456",
          creationDate: ts(-2000),
          expirationDate: ts(298000),
          factors: {
            user: { id: "700", organizationId: "300", verifiedAt: ts(-1000) },
            webAuthN: { verifiedAt: ts(0), userVerified: true },
          },
        },
      } as any);
    vi.mocked(workforceIdentityRequest).mockResolvedValue({
      receipt: "paypm-wf1.bound.signature",
      expiresAt: new Date(Date.now() + 60000).toISOString(),
    });
    expect(await completeWorkforceAction({ requestId, assertion: signed })).toHaveProperty("receipt");
    expect(vi.mocked(setSession).mock.calls[0][0].checks?.webAuthN?.credentialAssertionData).toEqual(signed);
    expect(workforceIdentityRequest).toHaveBeenCalledWith(
      `internal/v1/workforce-action-proofs/requests/${requestId}/complete`,
      { assertion: signed },
    );
    expect(deleteActionState).toHaveBeenCalled();
  });
  it.each(["provider-rejection", "provider-missing-uv", "provider-wrong-person", "provider-stale"])(
    "denies %s before receipt issuance",
    async (kind) => {
      const signed = assertion();
      vi.mocked(setSession).mockResolvedValue({ sessionToken: "rotated-provider-token" } as any);
      if (kind === "provider-rejection") vi.mocked(setSession).mockRejectedValue(new Error("provider rejected signature"));
      vi.mocked(getSession)
        .mockResolvedValueOnce({ session: base() } as any)
        .mockResolvedValueOnce({
          session: {
            id: "456",
            creationDate: ts(-120000),
            expirationDate: ts(180000),
            factors: {
              user: { id: kind === "provider-wrong-person" ? "999" : "700", organizationId: "300", verifiedAt: ts(-120000) },
              webAuthN: {
                verifiedAt: ts(kind === "provider-stale" ? -61000 : 0),
                userVerified: kind !== "provider-missing-uv",
              },
            },
          },
        } as any);
      expect(await completeWorkforceAction({ requestId, assertion: signed })).toHaveProperty("error");
      expect(workforceIdentityRequest).not.toHaveBeenCalled();
    },
  );
  it.each(["missing-uv", "changed-challenge", "changed-origin", "wrong-request", "changed-base"])(
    "rejects %s without calling provider assertion verification",
    async (kind) => {
      const signed = assertion();
      if (kind === "missing-uv") {
        const bytes = Buffer.from(signed.response.authenticatorData, "base64url");
        bytes[32] = 1;
        signed.response.authenticatorData = bytes.toString("base64url");
      }
      if (kind === "changed-challenge" || kind === "changed-origin")
        signed.response.clientDataJSON = Buffer.from(
          JSON.stringify({
            type: "webauthn.get",
            challenge: kind === "changed-challenge" ? "wrong" : challenge,
            origin: kind === "changed-origin" ? "https://evil.test" : "https://login.paypm.test",
          }),
        ).toString("base64url");
      if (kind === "changed-base") vi.mocked(getActionState).mockResolvedValue({ ...state(), baseSessionId: "999" });
      expect(
        await completeWorkforceAction({ requestId: kind === "wrong-request" ? "different" : requestId, assertion: signed }),
      ).toHaveProperty("error");
      expect(setSession).not.toHaveBeenCalled();
    },
  );
});
