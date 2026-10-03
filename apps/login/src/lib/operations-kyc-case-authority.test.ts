import { createHmac } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fixture from "../../test-fixtures/operations-kyc-case.json";
import {
  canonicalOperationsJson,
  operationsCommand,
  operationsExpected,
  readOperationsActionAuthority,
} from "./operations-action-authority";
import type { OperationsActionExpected, OperationsKycCaseCommand } from "./operations-action-store";
import { workforceAssertionHash } from "./workforce-assertion";
const expected = fixture.request.expected as OperationsActionExpected;
const command = fixture.request.command as OperationsKycCaseCommand;
const proofs = {
  idToken: "synthetic-signed-id",
  accessToken: "synthetic-access",
  nonce: "synthetic-original-nonce",
  clientId: expected.clientId,
};
const secret = "fixture-only-kyc-case-owner-separate-purpose-credential";
beforeEach(() => {
  vi.stubEnv(
    "PAYPM_OPERATIONS_KYC_ACTION_AUTHORITY_URL",
    "https://api.paypm.test/api/v1/internal/operations/authority/kyc/actions/current",
  );
  vi.stubEnv("PAYPM_OPERATIONS_KYC_ACTION_AUTHORITY_KEY_ID", "seed_ops_kyc_reader");
  vi.stubEnv("PAYPM_OPERATIONS_KYC_ACTION_AUTHORITY_API_KEY", secret);
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => Response.json(fixture.response)),
  );
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});
describe("separate Operations KYC case current owning wire", () => {
  it("independently verifies frozen native case/document state, action hash, raw HMAC and strict20 proof", async () => {
    expect(workforceAssertionHash(fixture.snapshot)).toBe(fixture.response.resource.stateHash);
    expect(workforceAssertionHash(fixture.canonicalMaterial)).toBe(expected.payloadHash);
    expect(JSON.parse(fixture.hmac.rawJSON)).toEqual(fixture.request);
    expect(fixture.hmac.signedBytes).toBe(
      `1791028810.00000019-0000-4000-8000-000000000000.POST.${fixture.hmac.path}.${fixture.hmac.rawJSON}`,
    );
    expect(fixture.hmac.header).toBe(
      `t=1791028810,n=00000019-0000-4000-8000-000000000000,v2=${createHmac("sha256", fixture.hmac.fixtureSecret).update(fixture.hmac.signedBytes).digest("hex")}`,
    );
    expect(Object.keys(fixture.proofResponse)).toHaveLength(20);
    expect(fixture.proofResponse.command).toEqual(command);
    expect(fixture.proofResponse.resource).toEqual(fixture.response.resource);
    expect(await readOperationsActionAuthority(expected, command, proofs)).toEqual({
      expected,
      command,
      capabilityDecisionId: fixture.response.capabilityDecisionId,
      resource: fixture.response.resource,
    });
  });
  it("signs only the exact distinct current owner path with the original private proof pair", async () => {
    await readOperationsActionAuthority(expected, command, proofs);
    const [url, options] = vi.mocked(fetch).mock.calls[0],
      h = new Headers(options!.headers);
    expect(String(url)).toBe(process.env.PAYPM_OPERATIONS_KYC_ACTION_AUTHORITY_URL);
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
  it.each(["verificationId", "walletEndUserId", "affectedPersonId", "level", "stateHash", "reviewOperationKey"])(
    "rejects changed current %s resource",
    async (field) => {
      vi.mocked(fetch).mockResolvedValueOnce(
        Response.json({ ...fixture.response, resource: { ...fixture.response.resource, [field]: "changed" } }),
      );
      await expect(readOperationsActionAuthority(expected, command, proofs)).rejects.toThrow();
    },
  );
  it("rejects self-affected action even if its attacker recomputes an otherwise matching hash", async () => {
    const resource = { ...fixture.response.resource, affectedPersonId: expected.personId };
    const altered = { ...expected, payloadHash: workforceAssertionHash({ ...fixture.canonicalMaterial, target: resource }) };
    vi.mocked(fetch).mockResolvedValueOnce(Response.json({ ...fixture.response, ...altered, resource }));
    await expect(readOperationsActionAuthority(altered, command, proofs)).rejects.toThrow();
  });
  it.each(["actor", "grantDecision", "decision", "reasons", "extra", "inactive"])(
    "denies %s owner corruption",
    async (kind) => {
      const result: any = structuredClone(fixture.response);
      if (kind === "actor") result.personId = fixture.response.resource.affectedPersonId;
      if (kind === "grantDecision") result.capabilityDecisionId = "forged";
      if (kind === "decision") result.command.decision = "approved";
      if (kind === "reasons") result.command.reasons = ["changed_document_decision"];
      if (kind === "extra") result.permissions = ["operations.admin"];
      if (kind === "inactive") result.active = false;
      vi.mocked(fetch).mockResolvedValueOnce(Response.json(result));
      await expect(readOperationsActionAuthority(expected, command, proofs)).rejects.toThrow();
    },
  );
  it("accepts only bounded command5 and relates terminal decisions to their immutable original review", () => {
    expect(operationsExpected(expected, "kyc")).toBe(true);
    expect(operationsCommand(command, "kyc")).toBe(true);
    for (const decision of ["approved", "rejected"] as const)
      expect(
        operationsCommand({ ...command, decision, reviewOperationKey: "00000020-0000-4000-8000-000000000000" }, "kyc"),
      ).toBe(true);
    for (const bad of [
      { ...command, actorId: expected.personId },
      { ...command, personId: expected.personId },
      { ...command, decision: "approved" },
      { ...command, reviewOperationKey: command.operationKey },
      { ...command, reasons: [] },
      { ...command, reasons: Array(11).fill("documents_checked") },
      { ...command, reasons: ["unbound free form"] },
      { ...command, reasons: ["x".repeat(81)] },
      { ...command, reasons: ["forged\nreason"] },
      { ...command, operationKey: "not-original-operation" },
    ])
      expect(operationsCommand(bad, "kyc")).toBe(false);
  });
  it.each(["settlement", "grant", "deployment-grant", "kyc-grant"] as const)(
    "never treats the %s family as case authority",
    (family) => {
      expect(operationsExpected(expected, family)).toBe(false);
      expect(operationsCommand(command, family)).toBe(false);
    },
  );
  it.each([
    "PAYPM_OPERATIONS_KYC_ACTION_BFF_TOKEN",
    "PAYPM_OPERATIONS_KYC_ACTION_CONSUMER_TOKEN",
    "PAYPM_OPERATIONS_KYC_GRANT_AUTHORITY_API_KEY",
    "PAYPM_OPERATIONS_ACTION_AUTHORITY_API_KEY",
    "PAYPM_OPERATIONS_DEPLOYMENT_GRANT_AUTHORITY_API_KEY",
  ])("rejects purpose reuse from %s before any reader effect", async (name) => {
    vi.stubEnv(name, secret);
    await expect(readOperationsActionAuthority(expected, command, proofs)).rejects.toThrow();
    expect(fetch).not.toHaveBeenCalled();
  });
  it("cannot borrow a KYC grant path or accept reader unavailability", async () => {
    vi.stubEnv(
      "PAYPM_OPERATIONS_KYC_ACTION_AUTHORITY_URL",
      "https://api.paypm.test/api/v1/internal/operations/authority/kyc-grants/actions/current",
    );
    await expect(readOperationsActionAuthority(expected, command, proofs)).rejects.toThrow();
    expect(fetch).not.toHaveBeenCalled();
  });
  it("denies an unavailable current reader", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(new Response("unavailable", { status: 503 }));
    await expect(readOperationsActionAuthority(expected, command, proofs)).rejects.toThrow();
  });
});
