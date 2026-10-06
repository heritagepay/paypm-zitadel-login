// @vitest-environment node
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fixture from "../../test-fixtures/identity-wallet-linkage.json";
import { readIdentityActionAuthority } from "./identity-action-authority";
import type { IdentityActionCommand, IdentityActionExpected } from "./identity-action-contract";
const command = fixture.command as IdentityActionCommand,
  expected = fixture.expected as IdentityActionExpected;
const pair = {
  idToken: "synthetic-id-token",
  accessToken: "synthetic-access-token",
  nonce: "synthetic-nonce",
  clientId: expected.clientId,
};
let calls: { url: string; body: unknown; headers: Headers }[];
beforeEach(() => {
  vi.stubEnv("PAYPM_WORKFORCE_IDENTITY_URL", "https://identity.fixture.test/api/");
  vi.stubEnv("PAYPM_WORKFORCE_IDENTITY_TOKEN_URL", "https://auth.fixture.test/oauth/v2/token");
  vi.stubEnv("PAYPM_IDENTITY_ACTION_IDENTITY_CLIENT_ID", "machine-fixture");
  vi.stubEnv("PAYPM_IDENTITY_ACTION_IDENTITY_CLIENT_SECRET", "synthetic-machine-secret");
  vi.stubEnv("PAYPM_IDENTITY_ACTION_IDENTITY_SCOPES", "openid");
  calls = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url, init) => {
      const u = String(url),
        headers = new Headers(init?.headers);
      if (u.endsWith("/oauth/v2/token")) return Response.json({ access_token: "synthetic-machine-bearer" });
      const body = JSON.parse(String(init?.body));
      calls.push({ url: u, body, headers });
      return Response.json({
        active: true,
        expected: body.expected,
        command: body.command,
        caseId: command.operationKey,
        ...(body.previous ? { previousRequestId: body.previous.requestId } : {}),
      });
    }),
  );
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});
describe("exact owning Identity current/continuation transport", () => {
  it("uses named current authority, machine bearer and original pair only in body", async () => {
    expect(await readIdentityActionAuthority(expected, command, pair)).toEqual({
      expected,
      command,
      caseId: command.operationKey,
    });
    expect(calls[0].url).toBe("https://identity.fixture.test/api/internal/v1/recovery-cases/actions/current");
    expect(calls[0].headers.get("authorization")).toBe("Bearer synthetic-machine-bearer");
    expect(calls[0].body).toEqual({ ...pair, expected, command });
    expect(calls[0].url).not.toContain(pair.accessToken);
  });
  it("carries exact original immutable previous tuple to the distinct continuation owner", async () => {
    const previous = { requestId: "64c2ca79-efdb-4975-a342-f4211a312dae", expected, proofId: null, stepSessionId: "901" };
    await readIdentityActionAuthority({ ...expected, baseSessionId: "999" }, command, pair, previous);
    expect(calls[0].url).toMatch(/\/actions\/continuations\/current$/);
    expect(calls[0].body).toMatchObject({ previous });
  });
  it.each(["extra", "inactive", "foreignCase", "changedScope", "changedCommand"])("denies owner drift: %s", async (mode) => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url) =>
        String(url).endsWith("/token")
          ? Response.json({ access_token: "synthetic-machine-bearer" })
          : Response.json({
              active: mode !== "inactive",
              expected: mode === "changedScope" ? { ...expected, environment: "production" } : expected,
              command: mode === "changedCommand" ? { ...command, purpose: "credential_recovery" } : command,
              caseId: mode === "foreignCase" ? expected.personId : command.operationKey,
              ...(mode === "extra" ? { grant: true } : {}),
            }),
      ),
    );
    await expect(readIdentityActionAuthority(expected, command, pair)).rejects.toThrow();
  });
  it("denies wrong paired client before any machine or authority request", async () => {
    await expect(readIdentityActionAuthority(expected, command, { ...pair, clientId: "ops" })).rejects.toThrow();
    expect(fetch).not.toHaveBeenCalled();
  });
});
