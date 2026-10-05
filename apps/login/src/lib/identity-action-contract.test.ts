// @vitest-environment node
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  assertIdentityCommand,
  identityActionCommand,
  identityActionExpected,
  identityWalletActions,
  sameIdentityBinding,
  sameIdentityOwner,
} from "./identity-action-contract";
const caseId = "119e1f4e-9501-48bc-9422-4c7e99db23d6";
export const linkageCommand = {
  purpose: "wallet_legacy_linkage" as const,
  operationKey: caseId,
  input: {
    caseId,
    revision: 1 as const,
    source: { operationId: "ed1bca0a-ebcc-4fb3-8dcd-bc42a62c9e3f", materialHash: "a".repeat(64) },
  },
};
export const linkageExpected = {
  personId: "e8821bca-be0e-40f3-a3e0-e71af332ae6c",
  issuer: "https://auth.paypm.test",
  providerSubject: "700",
  baseSessionId: "800",
  clientId: "identity@paypm",
  contextId: "300",
  appId: "identity-administration" as const,
  deploymentId: "heritagepay",
  environment: "sandbox" as const,
  action: identityWalletActions.intake,
  payloadHash: "b".repeat(64),
};
describe("finite Identity legacy-linkage contract", () => {
  it("matches independent Identity canonical-object hashing regardless of property order", () => {
    const canonical =
      '{"input":{"caseId":"119e1f4e-9501-48bc-9422-4c7e99db23d6","revision":1,"source":{"materialHash":"' +
      "a".repeat(64) +
      '","operationId":"ed1bca0a-ebcc-4fb3-8dcd-bc42a62c9e3f"}},"operationKey":"119e1f4e-9501-48bc-9422-4c7e99db23d6","purpose":"wallet_legacy_linkage"}';
    expect(sameIdentityBinding(linkageCommand, JSON.parse(canonical))).toBe(true);
    const hash = createHash("sha256").update(canonical).digest("hex");
    expect(hash).toBe("b74ce7d18b7578113a62c941fb484959d5e2deaac15e25a3510633ee4bc9fa9c");
  });
  it("allows only intake and approve/reject review on the same immutable case", () => {
    expect(identityActionCommand(linkageCommand)).toBe(true);
    expect(identityActionExpected(linkageExpected)).toBe(true);
    for (const decision of ["approve", "reject"] as const)
      assertIdentityCommand(
        { ...linkageExpected, action: identityWalletActions.review },
        { purpose: "wallet_legacy_linkage", operationKey: caseId, caseId, revision: 1, decision },
      );
  });
  it.each([
    { ...linkageCommand, purpose: "credential_recovery" },
    { ...linkageCommand, phone: "+2250000000000" },
    { ...linkageCommand, input: { ...linkageCommand.input, revision: 2 } },
    { ...linkageCommand, input: { ...linkageCommand.input, caseId: linkageExpected.personId } },
    { ...linkageCommand, input: { ...linkageCommand.input, source: { ...linkageCommand.input.source, accountId: caseId } } },
    { purpose: "wallet_legacy_linkage", operationKey: caseId, caseId, revision: 1, decision: "execute" },
  ])("denies expanded or changed command %#", (c) => expect(identityActionCommand(c)).toBe(false));
  it.each([
    { ...linkageExpected, action: "identity.wallet_legacy_linkage.intake" },
    { ...linkageExpected, appId: "paypm-operations" },
    { ...linkageExpected, providerSubject: "employee" },
    { ...linkageExpected, issuer: "https://auth.paypm.test/" },
    { ...linkageExpected, environment: "demo" },
    { ...linkageExpected, personId: undefined },
  ])("denies unregistered actor/namespace shape %#", (e) => expect(identityActionExpected(e)).toBe(false));
  it("permits renewed SID observation only, never changed owner/action/hash", () => {
    expect(sameIdentityOwner(linkageExpected, { ...linkageExpected, baseSessionId: "999" })).toBe(true);
    for (const change of [
      { personId: caseId },
      { providerSubject: "701" },
      { clientId: "ops" },
      { contextId: "301" },
      { payloadHash: "c".repeat(64) },
    ])
      expect(sameIdentityOwner(linkageExpected, { ...linkageExpected, ...change })).toBe(false);
    expect(() =>
      assertIdentityCommand({ ...linkageExpected, action: identityWalletActions.review }, linkageCommand),
    ).toThrow();
  });
});
