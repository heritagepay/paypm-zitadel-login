import { Code, ConnectError } from "@connectrpc/connect";
import { UserVerificationRequirement } from "@zitadel/proto/zitadel/session/v2/challenge_pb";
import { createHash, randomUUID } from "crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getSessionCookieById } from "../cookies";
import { ClassifiedConnectError } from "../grpc/interceptors/error-classification";
import { deleteActionState, getActionState, storeActionState } from "../workforce-action-state";
import { workforceAssertionHash } from "../workforce-assertion";
import { workforceIdentityRequest } from "../workforce-identity-client";
import { workforceEligible } from "../workforce-policy";
import { workforceProvider } from "../workforce-provider";
import { readWorkforceState } from "../workforce-state";
import { workforceStore } from "../workforce-store";
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
vi.mock("../workforce-store", () => ({ workforceStore: vi.fn() }));
vi.mock("../workforce-provider", () => ({ workforceProvider: vi.fn() }));
vi.mock("../workforce-revocations", () => ({ flushWorkforceRevocations: vi.fn() }));
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
  operationKey: randomUUID(),
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
    challengeId: requestId,
    sessionId: "123",
    userId: "700",
    clientId: "identity-client",
    requestId: "oidc_request",
    issuedAt: Date.now() - 10000,
    expiresAt: Date.now() + 28000000,
  });
  let row = {
    operation_key: command.operationKey,
    created_at: new Date(Date.now() - 10),
    expires_at: new Date(Date.now() + 299990),
    provider_started_at: null as Date | null,
    state: "reserved",
    identity_request_id: null as string | null,
  };
  const material = {
    sessionId: "456",
    sessionToken: "must-not-return",
    publicKey: { challenge, rpId: "login.paypm.test", userVerification: "required" },
  };
  vi.mocked(workforceStore).mockReturnValue({
    admission: vi.fn(async () => true),
    passkeyAttempt: vi.fn(async () => ({ first: true })),
    passkeyAttemptVerified: vi.fn(),
    passkeyAttemptFailed: vi.fn(),
    reserveAction: vi.fn(async () => row),
    claimAction: vi.fn(async () => true),
    actionCreated: vi.fn(async () => (row = { ...row, state: "created" })),
    actionMaterial: vi.fn(() => material),
    actionRegistered: vi.fn(async () => (row = { ...row, state: "registered", identity_request_id: requestId })),
    abandonAction: vi.fn(),
  } as any);
  vi.mocked(workforceProvider).mockResolvedValue({ findActionIntent: vi.fn(async () => "456") } as any);
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
        action: command.action,
        payloadHash: command.payloadHash,
        appId: command.appId,
        deploymentId: command.deploymentId,
        environment: command.environment,
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
  it("requires an operation UUID and does not create provider state before durable reservation", async () => {
    expect(await startWorkforceAction({ ...command, operationKey: "" })).toHaveProperty("error");
    expect(createSessionFromChecksAndChallenges).not.toHaveBeenCalled();
    vi.mocked(workforceStore().reserveAction).mockRejectedValueOnce(new Error("database unavailable"));
    expect(await startWorkforceAction(command)).toHaveProperty("error");
    expect(createSessionFromChecksAndChallenges).not.toHaveBeenCalled();
  });
  it("recovers a lost Identity registration through the same protected provider material and operation", async () => {
    vi.mocked(workforceIdentityRequest).mockRejectedValueOnce(new Error("response lost")).mockResolvedValue({ requestId });
    expect(await startWorkforceAction(command)).toHaveProperty("error");
    expect(await startWorkforceAction(command)).toHaveProperty("requestId", requestId);
    expect(createSessionFromChecksAndChallenges).toHaveBeenCalledTimes(1);
    expect(vi.mocked(workforceIdentityRequest).mock.calls[0]).toEqual(vi.mocked(workforceIdentityRequest).mock.calls[1]);
  });
  it("does not repeat an in-flight creation and retires only an exact metadata readback after an uncertain timeout", async () => {
    const store = workforceStore();
    vi.mocked(store.claimAction).mockResolvedValue(false);
    vi.mocked(store.reserveAction).mockResolvedValue({
      operation_key: command.operationKey,
      state: "reserved",
      created_at: new Date(Date.now() - 1000),
      expires_at: new Date(Date.now() + 290000),
      provider_started_at: new Date(),
    } as any);
    expect(await startWorkforceAction(command)).toHaveProperty("error");
    expect(createSessionFromChecksAndChallenges).not.toHaveBeenCalled();
    expect(workforceProvider).not.toHaveBeenCalled();
    vi.mocked(store.reserveAction).mockResolvedValue({
      operation_key: command.operationKey,
      state: "reserved",
      created_at: new Date(Date.now() - 20000),
      expires_at: new Date(Date.now() + 280000),
      provider_started_at: new Date(Date.now() - 15000),
    } as any);
    expect(await startWorkforceAction(command)).toHaveProperty("error");
    expect(createSessionFromChecksAndChallenges).not.toHaveBeenCalled();
    expect(store.abandonAction).toHaveBeenCalledWith(command.operationKey, "456");
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
          metadata: {
            ["paypm_workforce_passkey_request_" + requestId]: new TextEncoder().encode(workforceAssertionHash(signed)),
          },
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
  it("recovers a lost Identity completion response through exact provider marker readback without repeating the assertion", async () => {
    const signed = assertion(),
      completed = {
        id: "456",
        creationDate: ts(-2000),
        expirationDate: ts(298000),
        metadata: {
          ["paypm_workforce_passkey_request_" + requestId]: new TextEncoder().encode(workforceAssertionHash(signed)),
        },
        factors: {
          user: { id: "700", organizationId: "300", verifiedAt: ts(-1000) },
          webAuthN: { verifiedAt: ts(0), userVerified: true },
        },
      };
    vi.mocked(getSession).mockImplementation(
      async (command) => ({ session: command.sessionId === "123" ? base() : completed }) as any,
    );
    const store = vi.mocked(workforceStore).mock.results[0]?.value ?? workforceStore();
    store.passkeyAttempt.mockResolvedValueOnce({ first: true }).mockResolvedValue({ first: false });
    vi.mocked(setSession).mockResolvedValue({ sessionToken: "rotated-provider-token" } as any);
    vi.mocked(workforceIdentityRequest)
      .mockRejectedValueOnce(new Error("lost Identity reply"))
      .mockResolvedValue({ receipt: "paypm-wf1.exact.original", expiresAt: new Date(Date.now() + 60000).toISOString() });
    expect(await completeWorkforceAction({ requestId, assertion: signed })).toHaveProperty("error");
    expect(deleteActionState).not.toHaveBeenCalled();
    expect(await completeWorkforceAction({ requestId, assertion: signed })).toHaveProperty("receipt");
    expect(setSession).toHaveBeenCalledTimes(1);
  });
  it.each(["provider-rejection", "provider-missing-uv", "provider-wrong-person", "provider-stale"])(
    "denies %s before receipt issuance",
    async (kind) => {
      const signed = assertion();
      vi.mocked(setSession).mockResolvedValue({ sessionToken: "rotated-provider-token" } as any);
      if (kind === "provider-rejection")
        vi.mocked(setSession).mockRejectedValue(
          new ClassifiedConnectError(new ConnectError("provider rejected signature", Code.Unauthenticated)),
        );
      vi.mocked(getSession)
        .mockResolvedValueOnce({ session: base() } as any)
        .mockResolvedValueOnce({
          session: {
            id: "456",
            metadata: {
              ["paypm_workforce_passkey_request_" + requestId]: new TextEncoder().encode(workforceAssertionHash(signed)),
            },
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
