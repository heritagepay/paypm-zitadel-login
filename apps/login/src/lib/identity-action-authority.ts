import "server-only";
import {
  assertIdentityCommand,
  exactObject,
  identityActionPair,
  sameIdentityBinding,
  type IdentityActionBinding,
  type IdentityActionCommand,
  type IdentityActionExpected,
  type IdentityActionPair,
} from "./identity-action-contract";
import { workforceIdentityRequest } from "./workforce-identity-client";
export async function readIdentityActionAuthority(
  expected: IdentityActionExpected,
  command: IdentityActionCommand,
  pair: IdentityActionPair,
  previous?: { requestId: string; expected: IdentityActionExpected; proofId: string | null; stepSessionId: string | null },
) {
  assertIdentityCommand(expected, command);
  if (!identityActionPair(pair) || pair.clientId !== expected.clientId) throw new Error("Identity action unavailable");
  const result = await workforceIdentityRequest(
    (command.purpose === "wallet_legacy_linkage"
      ? "internal/v1/recovery-cases/actions/"
      : "internal/v1/staff-access/actions/") + (previous ? "continuations/current" : "current"),
    {
      ...pair,
      expected,
      command,
      ...(previous ? { previous } : {}),
    },
  );
  if (
    !exactObject(result, ["active", "expected", "command", "caseId", ...(previous ? ["previousRequestId"] : [])]) ||
    result.active !== true ||
    result.caseId !== command.operationKey ||
    !sameIdentityBinding(result.expected, expected) ||
    !sameIdentityBinding(result.command, command) ||
    (previous && result.previousRequestId !== previous.requestId)
  )
    throw new Error("Identity action unavailable");
  return { expected, command, caseId: command.operationKey } satisfies IdentityActionBinding;
}
