// @vitest-environment node
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fixture from "../../test-fixtures/identity-wallet-linkage.json";
import { readIdentityActionAuthority } from "./identity-action-authority";
import {
  assertIdentityCommand,
  identityActionCommand,
  identityActionExpected,
  type IdentityActionCommand,
  type IdentityActionExpected,
} from "./identity-action-contract";
import { identityStaffActions, staffActionCommand } from "./staff-action-contract";
import { workforceIdentityRequest } from "./workforce-identity-client";
const invitation = {
  purpose: "staff_invitation",
  operationKey: fixture.command.operationKey,
  input: { email: "staff@example.test", givenName: "Test", familyName: "Staff" },
};
const approval = {
  purpose: "staff_access_approval",
  operationKey: fixture.command.operationKey,
  requestId: fixture.command.operationKey,
  requestCommitment: "a".repeat(64),
};
const pair = {
  idToken: "synthetic-id",
  accessToken: "synthetic-access",
  nonce: "synthetic-nonce",
  clientId: fixture.expected.clientId,
};
beforeEach(() => {
  vi.stubEnv("PAYPM_WORKFORCE_IDENTITY_URL", "https://identity.fixture.test/api/");
  vi.stubEnv("PAYPM_WORKFORCE_IDENTITY_TOKEN_URL", "https://auth.fixture.test/oauth/v2/token");
  vi.stubEnv("PAYPM_WORKFORCE_IDENTITY_CLIENT_ID", "read-only-machine");
  vi.stubEnv("PAYPM_WORKFORCE_IDENTITY_CLIENT_SECRET", "read-only-synthetic-secret");
  vi.stubEnv("PAYPM_IDENTITY_ACTION_IDENTITY_CLIENT_ID", "action-only-machine");
  vi.stubEnv("PAYPM_IDENTITY_ACTION_IDENTITY_CLIENT_SECRET", "action-only-synthetic-secret");
  vi.stubEnv("PAYPM_IDENTITY_ACTION_IDENTITY_SCOPES", "openid");
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url, init) => {
      if (String(url).endsWith("/token")) return Response.json({ access_token: "synthetic-action-bearer" });
      const body = JSON.parse(String(init?.body));
      return Response.json({
        active: true,
        expected: body.expected,
        command: body.command,
        caseId: body.command.operationKey,
        ...(body.previous ? { previousRequestId: body.previous.requestId } : {}),
      });
    }),
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});
describe("Strict shared staff wire and dedicated producer transport", () => {
  it.each([invitation, approval])("admits closed staff purposes with exact corresponding action", (command) => {
    expect(staffActionCommand(command)).toBe(true);
    expect(identityActionCommand(command)).toBe(true);
    const action = command.purpose === "staff_invitation" ? identityStaffActions.invitation : identityStaffActions.approval;
    const expected = { ...fixture.expected, action };
    expect(identityActionExpected(expected)).toBe(true);
    expect(() => assertIdentityCommand(expected, command)).not.toThrow();
    expect(() => assertIdentityCommand({ ...expected, action: fixture.expected.action }, command)).toThrow();
  });
  it.each([
    { ...invitation, personId: fixture.expected.personId },
    { ...approval, role: "identity.staff.access.admin" },
    { ...invitation, purpose: "staff_bootstrap" },
    { ...invitation, input: { ...invitation.input, email: " STAFF@example.test " } },
    { ...approval, requestCommitment: "other" },
  ])("denies caller authority, unknown purpose and noncanonical fields", (command) =>
    expect(staffActionCommand(command)).toBe(false),
  );
  it.each([invitation, approval])("uses staff authority owner and never read-only machine secret", async (command) => {
    const expected = {
      ...fixture.expected,
      action: command.purpose === "staff_invitation" ? identityStaffActions.invitation : identityStaffActions.approval,
    } as IdentityActionExpected;
    await readIdentityActionAuthority(expected, command as IdentityActionCommand, pair);
    const calls = vi.mocked(fetch).mock.calls;
    expect(String(calls[1][0])).toBe("https://identity.fixture.test/api/internal/v1/staff-access/actions/current");
    expect(String(calls[0][1]?.body)).toContain("client_id=action-only-machine");
    expect(String(calls[0][1]?.body)).not.toContain("read-only");
    expect(new Headers(calls[1][1]?.headers).get("authorization")).toBe("Bearer synthetic-action-bearer");
  });
  it("carries original exact previous operation without a new challenge or actor selection", async () => {
    const command = approval as IdentityActionCommand,
      expected = { ...fixture.expected, action: identityStaffActions.approval } as IdentityActionExpected;
    const previous = { requestId: fixture.command.operationKey, expected, proofId: null, stepSessionId: "901" };
    await readIdentityActionAuthority(expected, command, pair, previous);
    const calls = vi.mocked(fetch).mock.calls;
    expect(String(calls[1][0])).toMatch(/staff-access\/actions\/continuations\/current$/);
    expect(JSON.parse(String(calls[1][1]?.body))).toMatchObject({ previous });
  });
  it.each([
    "PAYPM_IDENTITY_ACTION_IDENTITY_CLIENT_ID",
    "PAYPM_IDENTITY_ACTION_IDENTITY_CLIENT_SECRET",
    "PAYPM_IDENTITY_ACTION_IDENTITY_SCOPES",
  ])("fails closed when %s is absent", async (key) => {
    vi.stubEnv(key, "");
    await expect(workforceIdentityRequest("internal/v1/staff-access/actions/current", {})).rejects.toThrow();
    expect(fetch).not.toHaveBeenCalled();
  });
  it.each([
    ["PAYPM_IDENTITY_ACTION_IDENTITY_CLIENT_ID", "read-only-machine"],
    ["PAYPM_IDENTITY_ACTION_IDENTITY_CLIENT_SECRET", "read-only-synthetic-secret"],
  ])("denies reader/action credential reuse", async (key, value) => {
    vi.stubEnv(key, value);
    await expect(workforceIdentityRequest("internal/v1/staff-access/actions/current", {})).rejects.toThrow();
    expect(fetch).not.toHaveBeenCalled();
  });
  it.each([
    "internal/v1/people",
    "internal/v1/people/bind",
    "internal/v1/staff-access/actions/execute",
    "internal/v1/staff-access/actions/current?x=1",
  ])("denies unregistered machine writes: %s", async (path) => {
    await expect(workforceIdentityRequest(path, {})).rejects.toThrow();
    expect(fetch).not.toHaveBeenCalled();
  });
});
