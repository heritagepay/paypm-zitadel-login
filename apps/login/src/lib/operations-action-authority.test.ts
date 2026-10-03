import { createHmac, randomUUID } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import frozenOwner from "../../test-fixtures/operations-action-authority.json";
import {
  canonicalOperationsJson,
  operationsCommand,
  operationsExpected,
  readOperationsActionAuthority,
} from "./operations-action-authority";
import { workforceAssertionHash } from "./workforce-assertion";
const command = { operationKey: randomUUID(), merchantBusinessId: randomUUID(), organizationId: randomUUID() },
  resource = { merchantBusinessId: command.merchantBusinessId, organizationId: command.organizationId, currency: "XOF" };
const expected = {
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
  payloadHash: "",
};
expected.payloadHash = workforceAssertionHash({
  version: 1,
  action: expected.action,
  personId: expected.personId,
  appId: expected.appId,
  deploymentId: expected.deploymentId,
  environment: expected.environment,
  contextId: expected.contextId,
  target: resource,
  idempotencyKey: command.operationKey,
  input: {},
});
const proofs = {
    idToken: "synthetic-signed-id",
    accessToken: "synthetic-access",
    nonce: "synthetic-original-nonce",
    clientId: expected.clientId,
  },
  decisionId = randomUUID(),
  secret = "synthetic-api-key-for-exclusive-reader-purpose-only";
const reply = () => ({ active: true, ...expected, command, capabilityDecisionId: decisionId, resource });
beforeEach(() => {
  vi.stubEnv(
    "PAYPM_OPERATIONS_ACTION_AUTHORITY_URL",
    "https://api.paypm.test/api/v1/internal/operations/authority/actions/current",
  );
  vi.stubEnv("PAYPM_OPERATIONS_ACTION_AUTHORITY_KEY_ID", "seed_ops_reader");
  vi.stubEnv("PAYPM_OPERATIONS_ACTION_AUTHORITY_API_KEY", secret);
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => Response.json(reply())),
  );
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});
describe("Operations owning authority readback wire", () => {
  it("accepts the independently produced backend frozen authority/hash/HMAC fixture", async () => {
    expect(canonicalOperationsJson(frozenOwner.canonicalMaterial)).toBe(frozenOwner.canonicalUTF8);
    expect(workforceAssertionHash(frozenOwner.canonicalMaterial)).toBe(frozenOwner.payloadHash);
    expect(frozenOwner.signedUTF8).toBe(
      `${frozenOwner.timestamp}.${frozenOwner.nonce}.${frozenOwner.method}.${frozenOwner.path}.${frozenOwner.rawBody}`,
    );
    expect(frozenOwner.signatureHeader).toBe(
      `t=${frozenOwner.timestamp},n=${frozenOwner.nonce},v2=${createHmac("sha256", frozenOwner.fixtureHmacSecret).update(frozenOwner.signedUTF8).digest("hex")}`,
    );
    vi.mocked(fetch).mockResolvedValueOnce(Response.json(frozenOwner.response));
    const result = await readOperationsActionAuthority(
      frozenOwner.request.expected as any,
      frozenOwner.request.command,
      proofs,
    );
    expect(result.capabilityDecisionId).toBe(frozenOwner.response.capabilityDecisionId);
    expect(result.expected.payloadHash).toBe(frozenOwner.payloadHash);
  });
  it("sends exact canonical command plus separately authenticated original pair and valid HMACv2", async () => {
    expect(await readOperationsActionAuthority(expected, command, proofs)).toEqual({
      expected,
      command,
      capabilityDecisionId: decisionId,
      resource,
    });
    const [url, options] = vi.mocked(fetch).mock.calls[0];
    expect(String(url)).toBe(process.env.PAYPM_OPERATIONS_ACTION_AUTHORITY_URL);
    const h = new Headers(options!.headers),
      signature = h.get("X-Plug-Wallet-Signature")!,
      match = /^t=(\d+),n=([a-f0-9-]{36}),v2=([a-f0-9]{64})$/.exec(signature)!;
    expect(options!.body).toBe(canonicalOperationsJson({ expected, command }));
    expect(h.get("authorization")).toBe(`Bearer ${proofs.accessToken}`);
    expect(h.get("X-PayPM-Workforce-Id-Token")).toBe(proofs.idToken);
    expect(h.get("X-PayPM-Workforce-Nonce")).toBe(proofs.nonce);
    expect(match[3]).toBe(
      createHmac("sha256", secret)
        .update(`${match[1]}.${match[2]}.POST./api/v1/internal/operations/authority/actions/current.${options!.body}`)
        .digest("hex"),
    );
    expect(options!.redirect).toBe("error");
    expect(options!.cache).toBe("no-store");
  });
  it.each([
    "personId",
    "providerSubject",
    "baseSessionId",
    "contextId",
    "clientId",
    "appId",
    "deploymentId",
    "environment",
    "payloadHash",
  ])("denies a changed %s owner echo", async (field) => {
    vi.mocked(fetch).mockResolvedValue(Response.json({ ...reply(), [field]: "changed" }));
    await expect(readOperationsActionAuthority(expected, command, proofs)).rejects.toThrow("unavailable");
  });
  it("denies incorrect canonical resource/currency and arbitrary owner properties", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(Response.json({ ...reply(), resource: { ...resource, currency: "USD" } }))
      .mockResolvedValueOnce(Response.json({ ...reply(), role: "admin" }));
    await expect(readOperationsActionAuthority(expected, command, proofs)).rejects.toThrow();
    await expect(readOperationsActionAuthority(expected, command, proofs)).rejects.toThrow();
  });
  it("denies an altered operation or absent durable capability decision", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(Response.json({ ...reply(), command: { ...command, operationKey: randomUUID() } }))
      .mockResolvedValueOnce(Response.json({ ...reply(), capabilityDecisionId: null }));
    await expect(readOperationsActionAuthority(expected, command, proofs)).rejects.toThrow();
    await expect(readOperationsActionAuthority(expected, command, proofs)).rejects.toThrow();
  });
  it("denies unavailable owner and reused credential purposes", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(new Response("down", { status: 503 }));
    await expect(readOperationsActionAuthority(expected, command, proofs)).rejects.toThrow();
    vi.stubEnv("PAYPM_OPERATIONS_ACTION_BFF_TOKEN", secret);
    await expect(readOperationsActionAuthority(expected, command, proofs)).rejects.toThrow();
  });
  it("denies arbitrary action/actor fields and preserves existing non-v4 Person UUIDs", () => {
    expect(operationsExpected({ ...expected, action: "identity.recovery.review" })).toBe(false);
    expect(operationsExpected({ ...expected, actorId: expected.personId })).toBe(false);
    expect(operationsExpected({ ...expected, personId: "aabbccdd-aabb-7abb-8abb-aabbccddeeff" })).toBe(true);
    expect(operationsCommand({ ...command, role: "admin" })).toBe(false);
  });
});
