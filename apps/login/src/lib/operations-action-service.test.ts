import { UserVerificationRequirement } from "@zitadel/proto/zitadel/session/v2/challenge_pb";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import grantFixture from "../../test-fixtures/operations-governed-grant.json";
import { readOperationsActionAuthority } from "./operations-action-authority";
import {
  cancelOperationsPublicAction,
  completeOperationsPublicAction,
  consumeOperationsAction,
  readOperationsAction,
  readOperationsPublicChallenge,
  startOperationsAction,
} from "./operations-action-service";
import { operationsActionStore, type OperationsActionRow } from "./operations-action-store";
import { readOperationsAdmission } from "./operations-admission-reader";
import { workforceAssertionHash } from "./workforce-assertion";
import { workforcePolicy } from "./workforce-policy";
import { workforceProvider } from "./workforce-provider";
import { createSessionFromChecksAndChallenges, getSession, setSession } from "./zitadel";
vi.mock("next/headers", () => ({ headers: vi.fn(() => new Headers()) }));
vi.mock("./service-url", () => ({ getServiceConfig: () => ({ serviceConfig: { baseUrl: "https://auth.paypm.test" } }) }));
vi.mock("./operations-action-store", () => ({ operationsActionStore: vi.fn() }));
vi.mock("./operations-action-authority", async (original) => ({
  ...(await original<typeof import("./operations-action-authority")>()),
  readOperationsActionAuthority: vi.fn(),
}));
vi.mock("./operations-admission-reader", () => ({ readOperationsAdmission: vi.fn() }));
vi.mock("./workforce-store", () => ({ workforceStore: vi.fn(() => ({ pendingRevocations: async () => [] })) }));
vi.mock("./workforce-policy", () => ({ workforcePolicy: vi.fn() }));
vi.mock("./workforce-provider", () => ({ workforceProvider: vi.fn() }));
vi.mock("./workforce-revocations", () => ({ flushWorkforceRevocations: vi.fn() }));
vi.mock("./zitadel", () => ({ createSessionFromChecksAndChallenges: vi.fn(), getSession: vi.fn(), setSession: vi.fn() }));
const now = new Date("2026-10-03T18:00:00Z"),
  ts = (offset = 0) => ({ seconds: BigInt(Math.floor((now.getTime() + offset) / 1000)), nanos: 0 });
const challenge = Buffer.from("actual-issued-challenge-for-owned-test").toString("base64url"),
  id = randomUUID(),
  capability = randomBytes(32).toString("base64url"),
  callbackState = randomBytes(48).toString("base64url"),
  receipt = `paypm-ops1.${randomBytes(32).toString("base64url")}`;
const e = {
  personId: randomUUID(),
  issuer: "https://auth.paypm.test",
  providerSubject: "700",
  baseSessionId: "123",
  clientId: "ops@paypm",
  contextId: "300",
  appId: "paypm-operations",
  deploymentId: "heritagepay",
  environment: "production" as const,
  action: "operations.merchant.settlement.review" as const,
  payloadHash: "a".repeat(64),
};
const command = { operationKey: randomUUID(), merchantBusinessId: randomUUID(), organizationId: randomUUID() },
  binding = {
    expected: e,
    command,
    capabilityDecisionId: randomUUID(),
    resource: { merchantBusinessId: command.merchantBusinessId, organizationId: command.organizationId, currency: "XOF" },
  };
const material = {
  idToken: "synthetic-raw-id-token",
  accessToken: "synthetic-raw-access-token",
  nonce: "synthetic-original-nonce",
  clientId: e.clientId,
  capability,
  callbackState,
  callbackUrl: "https://ops.paypm.test/auth/workforce/actions/callback",
};
const provider = {
  sessionId: "456",
  sessionToken: "secret-provider-step-token",
  publicKey: { challenge, rpId: "login.paypm.test", userVerification: "required" },
};
let row: OperationsActionRow, store: any, session: any;
function assertion(flags = 5) {
  const auth = Buffer.alloc(37);
  createHash("sha256").update("login.paypm.test").digest().copy(auth);
  auth[32] = flags;
  return {
    id: "credential",
    rawId: "credential",
    type: "public-key",
    response: {
      clientDataJSON: Buffer.from(
        JSON.stringify({ type: "webauthn.get", challenge, origin: "https://login.paypm.test" }),
      ).toString("base64url"),
      authenticatorData: auth.toString("base64url"),
      signature: "actual-provider-verifies-signature",
      userHandle: null,
    },
  };
}
const auth = (purpose = "BFF") => ({ authorization: `Bearer ${purpose === "BFF" ? "b".repeat(40) : "c".repeat(40)}` });
const startBody = () => ({
  requestId: id,
  idToken: material.idToken,
  accessToken: material.accessToken,
  nonce: material.nonce,
  clientId: e.clientId,
  callbackState,
  action: e.action,
  payloadHash: e.payloadHash,
  command,
});
const start = (body = startBody()) =>
  startOperationsAction(
    new Request("https://login.paypm.test/private", { method: "POST", headers: auth(), body: JSON.stringify(body) }),
  );
const complete = (a = assertion(), origin = "https://login.paypm.test") =>
  completeOperationsPublicAction(
    new Request("https://login.paypm.test/public", {
      method: "POST",
      headers: { origin },
      body: JSON.stringify({ capability, assertion: a }),
    }),
    id,
  );
beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(now);
  vi.resetAllMocks();
  vi.stubEnv("PAYPM_WORKFORCE_PASSKEY_ORIGIN", "https://login.paypm.test");
  vi.stubEnv("PAYPM_WORKFORCE_PASSKEY_RP_ID", "login.paypm.test");
  vi.stubEnv("PAYPM_OPERATIONS_ACTION_BFF_TOKEN", "b".repeat(40));
  vi.stubEnv("PAYPM_OPERATIONS_ACTION_CONSUMER_TOKEN", "c".repeat(40));
  vi.stubEnv("PAYPM_OPERATIONS_ADMISSION_READER_TOKEN", "d".repeat(40));
  vi.stubEnv(
    "PAYPM_OPERATIONS_ACTION_CLIENT_POLICIES_JSON",
    JSON.stringify([{ clientId: e.clientId, callbackUrl: material.callbackUrl }]),
  );
  vi.mocked(workforcePolicy).mockReturnValue({
    issuer: e.issuer,
    organizationId: e.contextId,
    emailOtpReady: true,
    clientIds: [e.clientId],
  } as any);
  vi.mocked(readOperationsAdmission).mockImplementation(async () =>
    Response.json({
      active: true,
      ...e,
      plane: "workforce",
      authenticationClass: "workforce_limited",
      requestId: "oidc-request",
    }),
  );
  vi.mocked(readOperationsActionAuthority).mockResolvedValue(binding);
  row = {
    id,
    operation_key: command.operationKey,
    request_hash: "r".repeat(64),
    issuer: e.issuer,
    provider_subject: e.providerSubject,
    base_session_id: e.baseSessionId,
    client_id: e.clientId,
    request_id: "oidc-request",
    epoch: "0",
    binding,
    capability_hash: "h".repeat(64),
    caller_material_sealed: "sealed",
    state: "reserved",
    provider_started_at: null,
    provider_session_id: null,
    provider_material_sealed: null,
    assertion_hash: null,
    assertion_sealed: null,
    verification_started_at: null,
    verified_at: null,
    receipt_hash: null,
    receipt_sealed: null,
    receipt_expires_at: null,
    consumed_at: null,
    created_at: new Date(now.getTime() - 5000),
    expires_at: new Date(now.getTime() + 295000),
  };
  store = {
    reserve: vi.fn(async () => row),
    claimCreation: vi.fn(async () => true),
    created: vi.fn(
      async () =>
        (row = { ...row, state: "created", provider_session_id: provider.sessionId, provider_material_sealed: "sealed" }),
    ),
    caller: vi.fn(() => material),
    provider: vi.fn(() => provider),
    row: vi.fn(async () => row),
    capability: vi.fn(async () => row),
    clearExpired: vi.fn(),
    retire: vi.fn(),
    cancel: vi.fn(async () => (row = { ...row, state: "cancelled" })),
    attempt: vi.fn(async (_id, a) => ({
      first: true,
      row: (row = {
        ...row,
        assertion_hash: workforceAssertionHash(a),
        assertion_sealed: "sealed",
        verification_started_at: new Date(now.getTime() - 1000),
      }),
    })),
    assertion: vi.fn(() => assertion()),
    verified: vi.fn(
      async () =>
        (row = { ...row, state: "verified", verified_at: now, receipt_expires_at: new Date(now.getTime() + 60000) }),
    ),
    receipt: vi.fn(() => receipt),
    byReceipt: vi.fn(async () => row),
    consume: vi.fn(async () => (row = { ...row, state: "consumed", consumed_at: now })),
  };
  vi.mocked(operationsActionStore).mockReturnValue(store);
  vi.mocked(createSessionFromChecksAndChallenges).mockResolvedValue({
    sessionId: provider.sessionId,
    sessionToken: provider.sessionToken,
    challenges: { webAuthN: { publicKeyCredentialRequestOptions: { publicKey: provider.publicKey } } },
  } as any);
  vi.mocked(workforceProvider).mockResolvedValue({ findActionIntent: vi.fn(async () => "orphan-456") } as any);
  session = {
    id: provider.sessionId,
    creationDate: ts(-5000),
    expirationDate: ts(295000),
    factors: {
      user: { id: e.providerSubject, organizationId: e.contextId, verifiedAt: ts(-4000) },
      webAuthN: { userVerified: true, verifiedAt: ts() },
    },
    metadata: {},
  };
  vi.mocked(setSession).mockImplementation(async () => {
    session.metadata["paypm_operations_action_accept_" + id] = new TextEncoder().encode(row.assertion_hash!);
    return { sessionToken: "new-provider-token" } as any;
  });
  vi.mocked(getSession).mockImplementation(async () => ({ session }) as any);
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllEnvs();
});
describe("separate Operations-owned action ceremony", () => {
  function grant() {
    const grantBinding = {
      expected: {
        ...e,
        action: "operations.access.grant.review" as const,
        payloadHash: grantFixture.request.expected.payloadHash,
      },
      command: grantFixture.request.command,
      resource: grantFixture.response.resource,
      capabilityDecisionId: grantFixture.request.command.policyId,
    };
    row.binding = grantBinding as any;
    vi.mocked(readOperationsActionAuthority).mockResolvedValue(row.binding);
    vi.stubEnv("PAYPM_OPERATIONS_GRANT_BFF_TOKEN", "g".repeat(40));
    vi.stubEnv("PAYPM_OPERATIONS_GRANT_CONSUMER_TOKEN", "h".repeat(40));
    return grantBinding;
  }
  it("the separate grant family reserves and verifies one exact current action before its private consume", async () => {
    const g = grant();
    const startResponse = await startOperationsAction(
      new Request("https://login.paypm.test/private", {
        method: "POST",
        headers: { authorization: `Bearer ${"g".repeat(40)}` },
        body: JSON.stringify({
          ...startBody(),
          action: g.expected.action,
          payloadHash: g.expected.payloadHash,
          command: g.command,
        }),
      }),
      "grant",
    );
    expect(startResponse.status).toBe(200);
    expect((await complete()).status).toBe(200);
    const request = () =>
      new Request("https://login.paypm.test/private", {
        method: "POST",
        headers: { authorization: `Bearer ${"h".repeat(40)}` },
        body: JSON.stringify({ receipt, expected: g.expected, command: g.command }),
      });
    const consumed = await consumeOperationsAction(request(), false, "grant");
    expect(consumed.status).toBe(200);
    const result = await consumed.json();
    expect(Object.keys(result)).toHaveLength(20);
    expect(result).toMatchObject({
      proofId: id,
      ...g.expected,
      command: g.command,
      resource: g.resource,
      capabilityDecisionId: g.capabilityDecisionId,
      assurance: "paypm_fresh_operations_passkey",
    });
    expect((await consumeOperationsAction(request(), true, "grant")).status).toBe(200);
    expect(store.consume).toHaveBeenLastCalledWith(receipt, row.binding, true);
    expect(createSessionFromChecksAndChallenges).toHaveBeenCalledTimes(1);
  });
  it("rejects crossed grant and settlement routes or credentials before any provider or receipt effect", async () => {
    const g = grant();
    const grantBody = { ...startBody(), action: g.expected.action, payloadHash: g.expected.payloadHash, command: g.command };
    expect((await start(grantBody as any)).status).toBe(403);
    expect(
      (
        await startOperationsAction(
          new Request("https://login.paypm.test/private", {
            method: "POST",
            headers: { authorization: `Bearer ${"g".repeat(40)}` },
            body: JSON.stringify(startBody()),
          }),
          "grant",
        )
      ).status,
    ).toBe(403);
    expect(
      (
        await startOperationsAction(
          new Request("https://login.paypm.test/private", {
            method: "POST",
            headers: auth(),
            body: JSON.stringify(grantBody),
          }),
          "grant",
        )
      ).status,
    ).toBe(403);
    expect(createSessionFromChecksAndChallenges).not.toHaveBeenCalled();
    const consumeBody = { receipt, expected: g.expected, command: g.command };
    expect(
      (
        await consumeOperationsAction(
          new Request("https://login.paypm.test/private", {
            method: "POST",
            headers: auth("CONSUMER"),
            body: JSON.stringify(consumeBody),
          }),
        )
      ).status,
    ).toBe(403);
    expect(
      (
        await consumeOperationsAction(
          new Request("https://login.paypm.test/private", {
            method: "POST",
            headers: auth("CONSUMER"),
            body: JSON.stringify(consumeBody),
          }),
          false,
          "grant",
        )
      ).status,
    ).toBe(403);
    expect(store.consume).not.toHaveBeenCalled();
  });
  it("denies a revoked target or changed owner policy after provider acceptance without issuing a grant receipt", async () => {
    grant();
    row.state = "created";
    row.provider_session_id = provider.sessionId;
    vi.mocked(readOperationsActionAuthority)
      .mockResolvedValueOnce(row.binding)
      .mockRejectedValueOnce(new Error("current target or policy changed"));
    expect((await complete()).status).toBe(403);
    expect(setSession).toHaveBeenCalledTimes(1);
    expect(store.verified).not.toHaveBeenCalled();
  });
  it("reserves one caller request before required-UV provider creation and returns no proof tokens", async () => {
    const response = await start();
    expect(response.status).toBe(200);
    const result = await response.json();
    expect(result).toMatchObject({ requestId: id, expiresAt: row.expires_at.toISOString() });
    expect(new URL(result.redirectUrl).searchParams.get("capability")).toBe(capability);
    expect(JSON.stringify(result)).not.toContain(provider.sessionToken);
    expect(JSON.stringify(result)).not.toContain(receipt);
    expect(store.reserve.mock.invocationCallOrder[0]).toBeLessThan(
      vi.mocked(createSessionFromChecksAndChallenges).mock.invocationCallOrder[0],
    );
    expect(createSessionFromChecksAndChallenges).toHaveBeenCalledWith(
      expect.objectContaining({
        checks: expect.objectContaining({
          user: expect.objectContaining({ search: { case: "userId", value: e.providerSubject } }),
        }),
        challenges: expect.objectContaining({
          webAuthN: expect.objectContaining({ userVerificationRequirement: UserVerificationRequirement.REQUIRED }),
        }),
        metadata: { paypm_operations_action_intent: new TextEncoder().encode(id) },
      }),
    );
  });
  it("same stored request reads original capability/challenge without creating provider again", async () => {
    await start();
    expect((await start()).status).toBe(200);
    expect(createSessionFromChecksAndChallenges).toHaveBeenCalledTimes(1);
  });
  it("unknown creation retires only exact provider metadata instead of recreating a challenge", async () => {
    row.provider_started_at = new Date(now.getTime() - 11000);
    store.claimCreation.mockResolvedValue(false);
    expect((await start()).status).toBe(403);
    expect(createSessionFromChecksAndChallenges).not.toHaveBeenCalled();
    expect(store.retire).toHaveBeenCalledWith(id, "orphan-456");
    expect((await workforceProvider({} as any, e.contextId)).findActionIntent).toHaveBeenCalledWith(
      id,
      e.providerSubject,
      "paypm_operations_action_intent",
    );
  });
  it.each(["personId", "baseSessionId", "contextId", "environment"])(
    "rejects changed current %s admission before verification",
    async (field) => {
      row.state = "created";
      vi.mocked(readOperationsAdmission).mockImplementation(async () =>
        Response.json({
          active: true,
          ...e,
          [field]: "changed",
          plane: "workforce",
          authenticationClass: "workforce_limited",
          requestId: "oidc-request",
        }),
      );
      expect((await complete()).status).toBe(403);
      expect(setSession).not.toHaveBeenCalled();
    },
  );
  it.each([1, 4, 0])("rejects signed flags=%s before forwarding assertion", async (flags) => {
    row.state = "created";
    expect((await complete(assertion(flags))).status).toBe(403);
    expect(setSession).not.toHaveBeenCalled();
  });
  it("forwards the exact assertion once, binds acceptance metadata and returns only fixed callback IDs/state", async () => {
    row.state = "created";
    row.provider_session_id = provider.sessionId;
    const a = assertion(),
      response = await complete(a);
    expect(response.status).toBe(200);
    const result = await response.json(),
      url = new URL(result.callbackUrl);
    expect(url.origin + url.pathname).toBe(material.callbackUrl);
    expect([...url.searchParams.keys()].sort()).toEqual(["requestId", "state"]);
    expect(url.searchParams.get("state")).toBe(callbackState);
    expect(JSON.stringify(result)).not.toContain(receipt);
    expect(setSession).toHaveBeenCalledWith(
      expect.objectContaining({
        checks: expect.objectContaining({ webAuthN: expect.objectContaining({ credentialAssertionData: a }) }),
        metadata: { ["paypm_operations_action_accept_" + id]: new TextEncoder().encode(workforceAssertionHash(a)) },
      }),
    );
  });
  it("lost assertion result reads exact acceptance without resubmitting provider verification", async () => {
    row.state = "created";
    row.provider_session_id = provider.sessionId;
    row.verification_started_at = new Date(now.getTime() - 1000);
    row.assertion_hash = workforceAssertionHash(assertion());
    session.metadata["paypm_operations_action_accept_" + id] = new TextEncoder().encode(row.assertion_hash);
    store.attempt.mockResolvedValue({ first: false, row });
    expect((await complete()).status).toBe(200);
    expect(setSession).not.toHaveBeenCalled();
  });
  it.each(["wrong_identity", "missing_uv", "stale_factor", "missing_marker"])(
    "rejects provider %s after exact assertion",
    async (issue) => {
      row.state = "created";
      row.provider_session_id = provider.sessionId;
      if (issue === "wrong_identity") session.factors.user.id = "999";
      if (issue === "missing_uv") session.factors.webAuthN.userVerified = false;
      if (issue === "stale_factor") session.factors.webAuthN.verifiedAt = ts(-61000);
      if (issue === "missing_marker") vi.mocked(setSession).mockResolvedValue({ sessionToken: "new" } as any);
      expect((await complete()).status).toBe(403);
      expect(store.verified).not.toHaveBeenCalled();
    },
  );
  it("owner grant revocation and wrong Origin deny before provider verification", async () => {
    row.state = "created";
    vi.mocked(readOperationsActionAuthority).mockRejectedValue(new Error("revoked"));
    expect((await complete()).status).toBe(403);
    expect(setSession).not.toHaveBeenCalled();
    vi.mocked(readOperationsActionAuthority).mockResolvedValue(binding);
    expect((await complete(assertion(), "https://attacker.test")).status).toBe(403);
    expect(setSession).not.toHaveBeenCalled();
  });
  it("denies caller actor fields, reused purpose keys and missing callback policy", async () => {
    expect((await start({ ...startBody(), actorId: e.personId } as any)).status).toBe(403);
    expect(createSessionFromChecksAndChallenges).not.toHaveBeenCalled();
    vi.stubEnv("PAYPM_OPERATIONS_ACTION_BFF_TOKEN", "c".repeat(40));
    expect((await start()).status).toBe(403);
    vi.stubEnv("PAYPM_OPERATIONS_ACTION_BFF_TOKEN", "b".repeat(40));
    vi.stubEnv("PAYPM_OPERATIONS_ACTION_CLIENT_POLICIES_JSON", "[]");
    expect((await start()).status).toBe(403);
  });
  it("public challenge returns only bounded actual options and rechecks current owner", async () => {
    row.state = "created";
    const response = await readOperationsPublicChallenge(new Request("https://login.paypm.test/public"), id, capability);
    expect(await response.json()).toEqual({
      requestId: id,
      action: e.action,
      publicKey: provider.publicKey,
      expiresAt: row.expires_at.toISOString(),
      returnUrl: "https://ops.paypm.test",
    });
    expect(readOperationsActionAuthority).toHaveBeenCalled();
  });
  it("private terminal/consume use separate purpose and exact current fresh provider proof", async () => {
    row.state = "created";
    row.provider_session_id = provider.sessionId;
    expect((await complete()).status).toBe(200);
    const read = await readOperationsAction(
      new Request("https://login.paypm.test/read", {
        method: "POST",
        headers: auth(),
        body: JSON.stringify({ expected: e, command }),
      }),
      id,
    );
    expect((await read.json()).receipt).toBe(receipt);
    const response = await consumeOperationsAction(
      new Request("https://login.paypm.test/consume", {
        method: "POST",
        headers: auth("CONSUMER"),
        body: JSON.stringify({ receipt, expected: e, command }),
      }),
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      proofId: id,
      proofSessionId: provider.sessionId,
      assurance: "paypm_fresh_operations_passkey",
      consumedAt: now.toISOString(),
      ...e,
    });
  });
  it("private consume rejects altered command and an Identity receipt", async () => {
    row.state = "verified";
    row.provider_session_id = provider.sessionId;
    row.verified_at = now;
    row.receipt_expires_at = new Date(now.getTime() + 60000);
    const send = (body: unknown) =>
      consumeOperationsAction(
        new Request("https://login.paypm.test/private", {
          method: "POST",
          headers: auth("CONSUMER"),
          body: JSON.stringify(body),
        }),
      );
    expect((await send({ receipt, expected: { ...e, payloadHash: "b".repeat(64) }, command })).status).toBe(403);
    expect((await send({ receipt: "paypm-wf1.identity-proof", expected: e, command })).status).toBe(403);
    expect(store.consume).not.toHaveBeenCalled();
  });
  it("cancellation persists before callback and a later read returns no receipt", async () => {
    row.state = "created";
    const response = await cancelOperationsPublicAction(
      new Request("https://login.paypm.test/public", {
        method: "POST",
        headers: { origin: "https://login.paypm.test" },
        body: JSON.stringify({ capability }),
      }),
      id,
    );
    expect(response.status).toBe(200);
    expect(store.cancel).toHaveBeenCalledWith(id);
    const terminal = await readOperationsAction(
      new Request("https://login.paypm.test/read", {
        method: "POST",
        headers: auth(),
        body: JSON.stringify({ expected: e, command }),
      }),
      id,
    );
    expect(await terminal.json()).toEqual({
      requestId: id,
      state: "cancelled",
      expected: e,
      command,
      capabilityDecisionId: binding.capabilityDecisionId,
    });
    expect(store.receipt).not.toHaveBeenCalled();
  });
});
