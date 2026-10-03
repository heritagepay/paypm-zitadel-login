import { createHmac } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fixture from "../../test-fixtures/operations-deployment-grant.json";
import {
  canonicalOperationsJson,
  operationsCommand,
  operationsExpected,
  readOperationsActionAuthority,
} from "./operations-action-authority";
import type { OperationsActionExpected } from "./operations-action-store";
import { workforceAssertionHash } from "./workforce-assertion";
const expected = fixture.request.expected as OperationsActionExpected,
  command = fixture.request.command;
const proofs = {
  idToken: "synthetic-signed-id",
  accessToken: "synthetic-access",
  nonce: "synthetic-original-nonce",
  clientId: expected.clientId,
};
const secret = "fixture-only-grant-owner-separate-purpose-credential";
beforeEach(() => {
  vi.stubEnv(
    "PAYPM_OPERATIONS_DEPLOYMENT_GRANT_AUTHORITY_URL",
    "https://api.paypm.test/api/v1/internal/operations/authority/deployment-grants/actions/current",
  );
  vi.stubEnv("PAYPM_OPERATIONS_DEPLOYMENT_GRANT_AUTHORITY_KEY_ID", "seed_ops_grant_reader");
  vi.stubEnv("PAYPM_OPERATIONS_DEPLOYMENT_GRANT_AUTHORITY_API_KEY", secret);
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => Response.json(fixture.response)),
  );
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});
describe("separate Operations deployment read grant owning wire", () => {
  it("independently qualifies the actual backend hash, policy, HMAC and twenty-field proof fixture", async () => {
    expect(workforceAssertionHash(fixture.ownerPolicy)).toBe(fixture.response.resource.policyHash);
    expect(workforceAssertionHash(fixture.canonicalMaterial)).toBe(expected.payloadHash);
    expect(JSON.parse(fixture.hmac.rawJSON)).toEqual(fixture.request);
    expect(fixture.hmac.signedBytes).toBe(
      `1791028802.00000010-0000-4000-8000-000000000000.POST.${fixture.hmac.path}.${fixture.hmac.rawJSON}`,
    );
    expect(fixture.hmac.header).toBe(
      `t=1791028802,n=00000010-0000-4000-8000-000000000000,v2=${createHmac("sha256", fixture.hmac.fixtureSecret).update(fixture.hmac.signedBytes).digest("hex")}`,
    );
    expect(Object.keys(fixture.proofResponse)).toHaveLength(20);
    expect(fixture.proofResponse.command).toEqual(command);
    expect(fixture.proofResponse.resource).toEqual(fixture.response.resource);
    expect(await readOperationsActionAuthority(expected, command as any, proofs)).toEqual({
      expected,
      command,
      capabilityDecisionId: command.policyId,
      resource: fixture.response.resource,
    });
  });
  it("uses only the separate exact reader path and signed raw command with the original pair", async () => {
    await readOperationsActionAuthority(expected, command as any, proofs);
    const [url, options] = vi.mocked(fetch).mock.calls[0],
      h = new Headers(options!.headers);
    expect(String(url)).toBe(process.env.PAYPM_OPERATIONS_DEPLOYMENT_GRANT_AUTHORITY_URL);
    expect(options!.body).toBe(canonicalOperationsJson({ expected, command }));
    expect(h.get("authorization")).toBe(`Bearer ${proofs.accessToken}`);
    expect(h.get("X-PayPM-Workforce-Id-Token")).toBe(proofs.idToken);
    expect(h.get("X-PayPM-Workforce-Nonce")).toBe(proofs.nonce);
    const match = /^t=(\d+),n=([a-f0-9-]{36}),v2=([a-f0-9]{64})$/.exec(h.get("X-Plug-Wallet-Signature")!)!;
    expect(match[3]).toBe(
      createHmac("sha256", secret)
        .update(`${match[1]}.${match[2]}.POST.${fixture.hmac.path}.${options!.body}`)
        .digest("hex"),
    );
    expect(options!.redirect).toBe("error");
    expect(options!.cache).toBe("no-store");
  });
  it.each(["review", "approve", "revoke"])("accepts only a grant command for %s", (action) => {
    expect(
      operationsExpected({ ...expected, action: `operations.access.deployment-grant.${action}` }, "deployment-grant"),
    ).toBe(true);
    expect(operationsExpected({ ...expected, action: `operations.access.deployment-grant.${action}` })).toBe(false);
    expect(operationsCommand(command, "deployment-grant")).toBe(true);
    expect(operationsCommand(command)).toBe(false);
    expect(
      operationsCommand(
        {
          operationKey: command.operationKey,
          merchantBusinessId: fixture.canonicalMaterial.personId,
          organizationId: fixture.canonicalMaterial.personId,
        },
        "deployment-grant",
      ),
    ).toBe(false);
  });
  it.each(["policyHash", "policyId", "targetPersonId", "targetAuthentication", "capability"])(
    "denies altered %s resource even with the same actor",
    async (field) => {
      vi.mocked(fetch).mockResolvedValueOnce(
        Response.json({ ...fixture.response, resource: { ...fixture.response.resource, [field]: "changed" } }),
      );
      await expect(readOperationsActionAuthority(expected, command as any, proofs)).rejects.toThrow();
    },
  );
  it.each(["actor", "policyDecision", "commandReason", "commandExpiry", "extra", "inactive"])(
    "denies %s owner corruption",
    async (kind) => {
      const result: any = structuredClone(fixture.response);
      if (kind === "actor") result.personId = command.targetPersonId;
      if (kind === "policyDecision") result.capabilityDecisionId = command.targetPersonId;
      if (kind === "commandReason") result.command.reason = "Changed reviewed reason";
      if (kind === "commandExpiry") result.command.expiresAt = "2026-10-04T13:00:00.000Z";
      if (kind === "extra") result.permissions = ["operations.admin"];
      if (kind === "inactive") result.active = false;
      vi.mocked(fetch).mockResolvedValueOnce(Response.json(result));
      await expect(readOperationsActionAuthority(expected, command as any, proofs)).rejects.toThrow();
    },
  );
  it.each(["bff", "consumer", "settlementReader", "wrongPath", "unavailable"])(
    "denies %s purpose or transport failure",
    async (kind) => {
      if (kind === "bff") vi.stubEnv("PAYPM_OPERATIONS_DEPLOYMENT_GRANT_BFF_TOKEN", secret);
      if (kind === "consumer") vi.stubEnv("PAYPM_OPERATIONS_DEPLOYMENT_GRANT_CONSUMER_TOKEN", secret);
      if (kind === "settlementReader") vi.stubEnv("PAYPM_OPERATIONS_ACTION_AUTHORITY_API_KEY", secret);
      if (kind === "wrongPath")
        vi.stubEnv(
          "PAYPM_OPERATIONS_DEPLOYMENT_GRANT_AUTHORITY_URL",
          "https://api.paypm.test/api/v1/internal/operations/authority/actions/current",
        );
      if (kind === "unavailable") vi.mocked(fetch).mockResolvedValueOnce(new Response("down", { status: 503 }));
      await expect(readOperationsActionAuthority(expected, command as any, proofs)).rejects.toThrow();
    },
  );
  it("rejects unregistered permissions, unqualified subject, unbound reason/expiry and caller fields", () => {
    for (const bad of [
      { ...command, capability: "identity.staff.access.grant" },
      { ...command, capability: "operations.merchant.settlement.read" },
      { ...command, capability: "operations.transactions.execute" },
      { ...command, merchantBusinessId: expected.personId },
      { ...command, targetAuthentication: { ...command.targetAuthentication, subject: "commercial-uuid" } },
      { ...command, reason: "  Reviewed reason  " },
      { ...command, expiresAt: "not-a-time" },
      { ...command, actorId: expected.personId },
    ])
      expect(operationsCommand(bad, "deployment-grant")).toBe(false);
  });
  it("does not accept the company grant family or borrow its credentials", async () => {
    expect(operationsExpected(expected, "grant")).toBe(false);
    expect(operationsCommand(command, "grant")).toBe(false);
    vi.stubEnv("PAYPM_OPERATIONS_GRANT_AUTHORITY_API_KEY", secret);
    await expect(readOperationsActionAuthority(expected, command as any, proofs)).rejects.toThrow();
    expect(fetch).not.toHaveBeenCalled();
  });
});
