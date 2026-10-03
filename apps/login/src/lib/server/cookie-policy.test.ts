import { beforeEach, describe, expect, it, vi } from "vitest";
import { addSessionToCookie, updateSessionCookie } from "../cookies";
import { createSessionFromChecksAndChallenges, getSession, setSession } from "../zitadel";
import { createSessionAndUpdateCookie, setSessionAndUpdateCookie } from "./cookie";
vi.mock("next/headers", () => ({ headers: vi.fn(() => new Headers()) }));
vi.mock("../service-url", () => ({ getServiceConfig: () => ({ serviceConfig: { baseUrl: "https://auth.example.com" } }) }));
vi.mock("../cookies", () => ({ addSessionToCookie: vi.fn(), updateSessionCookie: vi.fn() }));
vi.mock("../zitadel", () => ({
  createSessionFromChecksAndChallenges: vi.fn(),
  createSessionForUserIdAndIdpIntent: vi.fn(),
  getSession: vi.fn(),
  setSession: vi.fn(),
  getSecuritySettings: vi.fn(),
}));
const timestamp = (time: number) => ({ seconds: BigInt(Math.floor(time / 1000)), nanos: (time % 1000) * 1000000 });
const now = Date.now();
const session = () =>
  ({
    id: "session",
    creationDate: timestamp(now - 7 * 3600000 - 1800000),
    expirationDate: timestamp(now + 12 * 3600000),
    factors: { user: { id: "user", loginName: "staff@example.com", organizationId: "ops-org" } },
  }) as any;
beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(updateSessionCookie).mockResolvedValue(undefined);
});
describe("provider session lifetime writes", () => {
  it("writes an explicit 8h cap to provider creation", async () => {
    vi.mocked(createSessionFromChecksAndChallenges).mockResolvedValue({
      sessionId: "session",
      sessionToken: "opaque-provider-token",
    } as any);
    vi.mocked(getSession).mockResolvedValue({ session: session() } as any);
    await createSessionAndUpdateCookie({
      checks: {} as any,
      requestId: "oidc_request",
      lifetime: { seconds: BigInt(86400), nanos: 0 } as any,
    });
    expect(vi.mocked(createSessionFromChecksAndChallenges).mock.calls[0][0].lifetime.seconds).toBe(BigInt(28800));
    expect(addSessionToCookie).toHaveBeenCalled();
  });
  it("uses live provider creation and expiry, never attacker-modified cookie timestamps", async () => {
    const original = session();
    const refreshed = { ...original, expirationDate: timestamp(now + 1790000) };
    vi.mocked(getSession)
      .mockResolvedValueOnce({ session: original } as any)
      .mockResolvedValueOnce({ session: refreshed } as any);
    vi.mocked(setSession).mockResolvedValue({ sessionToken: "rotated-provider-token" } as any);
    await setSessionAndUpdateCookie({
      recentCookie: {
        id: "session",
        token: "current-provider-token",
        loginName: "fake-login",
        creationTs: String(now + 24 * 3600000),
        expirationTs: String(now + 48 * 3600000),
        changeTs: "",
      },
      requestId: "oidc_request",
      lifetime: { seconds: BigInt(86400), nanos: 0 } as any,
    });
    const update = vi.mocked(setSession).mock.calls[0][0];
    expect(Number(update.lifetime.seconds)).toBeLessThanOrEqual(1800);
    expect(Number(update.lifetime.seconds)).toBeGreaterThan(1700);
    const cookie = vi.mocked(updateSessionCookie).mock.calls[0][0].session;
    expect(cookie.loginName).toBe("staff@example.com");
    expect(cookie.creationTs).toBe(String(now - 7 * 3600000 - 1800000));
    expect(cookie.expirationTs).toBe(String(now + 1790000));
  });
  it("does not mutate an indefinite provider session", async () => {
    vi.mocked(getSession).mockResolvedValue({ session: { ...session(), expirationDate: undefined } } as any);
    await expect(
      setSessionAndUpdateCookie({
        recentCookie: {
          id: "session",
          token: "token",
          loginName: "staff",
          creationTs: String(now),
          expirationTs: String(now + 3600000),
          changeTs: "",
        },
        lifetime: { seconds: BigInt(600), nanos: 0 } as any,
      }),
    ).rejects.toThrow();
    expect(setSession).not.toHaveBeenCalled();
  });
});
