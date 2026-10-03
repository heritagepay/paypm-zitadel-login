import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { denyUnreservedWorkforceOtp } from "./workforce-otp-boundary";
import { getAuthRequest, getUserByID } from "./zitadel";
vi.mock("./zitadel", () => ({ getAuthRequest: vi.fn(), getUserByID: vi.fn(), listUsers: vi.fn() }));
const config = { baseUrl: "https://auth.paypm.test" };
beforeEach(() => {
  vi.resetAllMocks();
  vi.stubEnv("PAYPM_WORKFORCE_ORGANIZATION_ID", "300");
  vi.stubEnv("PAYPM_WORKFORCE_ISSUER", "https://auth.paypm.test");
  vi.stubEnv("PAYPM_WORKFORCE_OIDC_CLIENT_IDS", "staff");
  vi.stubEnv("PAYPM_WORKFORCE_EMAIL_OTP_READY", "true");
});
afterEach(() => vi.unstubAllEnvs());
describe("workforce generic OTP boundary", () => {
  it("blocks existing workforce session OTP checks and challenges before provider effects", async () => {
    for (const v of [
      { checks: { otpEmail: { code: "123456" } } },
      { challenges: { otpEmail: { deliveryType: { case: "sendCode", value: {} } } } },
    ])
      await expect(
        denyUnreservedWorkforceOtp({
          serviceConfig: config,
          session: { factors: { user: { organizationId: "300" } } } as any,
          ...v,
        } as any),
      ).rejects.toThrow("durable");
  });
  it("blocks a workforce user discovery session or registered auth request even if caller omits organization", async () => {
    vi.mocked(getUserByID).mockResolvedValue({ user: { details: { resourceOwner: "300" } } } as any);
    await expect(
      denyUnreservedWorkforceOtp({
        serviceConfig: config,
        checks: { user: { search: { case: "userId", value: "700" } } } as any,
        challenges: { otpEmail: {} } as any,
      }),
    ).rejects.toThrow("durable");
    vi.mocked(getAuthRequest).mockResolvedValue({ authRequest: { clientId: "staff" } } as any);
    await expect(
      denyUnreservedWorkforceOtp({
        serviceConfig: config,
        requestId: "oidc_owned",
        checks: { otpEmail: { code: "123456" } } as any,
      }),
    ).rejects.toThrow("durable");
  });
  it("preserves the readiness-off legacy flow and separate provider user categories", async () => {
    vi.stubEnv("PAYPM_WORKFORCE_EMAIL_OTP_READY", "false");
    await expect(
      denyUnreservedWorkforceOtp({
        serviceConfig: config,
        session: { factors: { user: { organizationId: "300" } } } as any,
        checks: { otpEmail: { code: "123456" } } as any,
      }),
    ).resolves.toBeUndefined();
    vi.stubEnv("PAYPM_WORKFORCE_EMAIL_OTP_READY", "true");
    await expect(
      denyUnreservedWorkforceOtp({
        serviceConfig: config,
        session: { factors: { user: { organizationId: "999" } } } as any,
        checks: { otpEmail: { code: "123456" } } as any,
      }),
    ).resolves.toBeUndefined();
  });
});
