import type { User } from "@zitadel/proto/zitadel/user/v2/user_pb";
import { UserState } from "@zitadel/proto/zitadel/user/v2/user_pb";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  identityWorkforceEligibility,
  workforceClientMode,
  workforceEligible,
  workforcePolicy,
  workforceSelfRegistrationDenied,
} from "./workforce-policy";
import { getAuthRequest } from "./zitadel";
vi.mock("./zitadel", () => ({ getAuthRequest: vi.fn() }));
const user = (): User =>
  ({
    userId: "12345",
    state: UserState.ACTIVE,
    details: { resourceOwner: "54321" },
    type: { case: "human", value: { email: { email: "staff@example.com", isVerified: true } } },
  }) as any;
beforeEach(() => {
  vi.stubEnv("PAYPM_WORKFORCE_ORGANIZATION_ID", "54321");
  vi.stubEnv("PAYPM_WORKFORCE_ISSUER", "https://auth.example.com");
  vi.stubEnv("PAYPM_WORKFORCE_OIDC_CLIENT_IDS", "approved-client");
  vi.stubEnv("PAYPM_WORKFORCE_EMAIL_OTP_READY", "false");
  vi.stubEnv("PAYPM_WORKFORCE_IDENTITY_URL", "");
  vi.stubEnv("PAYPM_WORKFORCE_BOOTSTRAP_MODE", "");
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe("workforce invitation authority", () => {
  it("requires exact exhaustive current client policies and never treats an unknown native console as limited", () => {
    vi.stubEnv("PAYPM_WORKFORCE_OIDC_CLIENT_IDS", "approved-client,privileged-console");
    for (const rows of [
      null,
      [],
      [{ clientId: "approved-client", mode: "limited" }],
      [
        { clientId: "approved-client", mode: "limited" },
        { clientId: "approved-client", mode: "fresh_passkey" },
      ],
      [
        { clientId: "approved-client", mode: "limited" },
        { clientId: "privileged-console", mode: "unknown" },
      ],
    ]) {
      vi.stubEnv("PAYPM_WORKFORCE_OIDC_ADMISSION_POLICIES_JSON", JSON.stringify(rows));
      expect(workforceClientMode("approved-client")).toBeUndefined();
    }
    vi.stubEnv(
      "PAYPM_WORKFORCE_OIDC_ADMISSION_POLICIES_JSON",
      JSON.stringify([
        { clientId: "approved-client", mode: "limited" },
        { clientId: "privileged-console", mode: "fresh_passkey" },
      ]),
    );
    expect(workforceClientMode("approved-client")).toBe("limited");
    expect(workforceClientMode("privileged-console")).toBe("fresh_passkey");
    expect(workforceClientMode("unregistered")).toBeUndefined();
  });
  it("defaults OTP primary readiness off and denies unavailable Identity", async () => {
    expect(workforcePolicy()?.emailOtpReady).toBe(false);
    expect(await workforceEligible(user(), "approved-client", "login")).toBe(false);
  });
  it("denies absent or malformed category policy", () => {
    vi.stubEnv("PAYPM_WORKFORCE_ORGANIZATION_ID", "");
    expect(workforcePolicy()).toBeUndefined();
    vi.stubEnv("PAYPM_WORKFORCE_ORGANIZATION_ID", "54321");
    vi.stubEnv("PAYPM_WORKFORCE_ISSUER", "http://auth.example.com");
    expect(workforcePolicy()).toBeUndefined();
  });
  it("permits only exact qualification invite subjects with verified active email and registered clients", async () => {
    vi.stubEnv("PAYPM_WORKFORCE_BOOTSTRAP_MODE", "qualification");
    vi.stubEnv("PAYPM_WORKFORCE_BOOTSTRAP_INVITED_USER_IDS", "12345");
    expect(await workforceEligible(user(), "approved-client", "login")).toBe(true);
    expect(await workforceEligible({ ...user(), userId: "99999" }, "approved-client", "login")).toBe(false);
    expect(await workforceEligible(user(), "commercial-client", "login")).toBe(false);
    const unverified = user();
    if (unverified.type.case === "human") unverified.type.value.email!.isVerified = false;
    expect(await workforceEligible(unverified, "approved-client", "login")).toBe(false);
    expect(await workforceEligible({ ...user(), state: UserState.INACTIVE }, "approved-client", "login")).toBe(false);
  });
  it("cannot activate the bootstrap allowlist in production", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("PAYPM_WORKFORCE_BOOTSTRAP_MODE", "qualification");
    vi.stubEnv("PAYPM_WORKFORCE_BOOTSTRAP_INVITED_USER_IDS", "12345");
    expect(await workforceEligible(user(), "approved-client", "login")).toBe(false);
  });
  it("denies public staff creation in OPS or a registered workforce request", async () => {
    expect(await workforceSelfRegistrationDenied({ baseUrl: "https://auth.example.com" }, "54321", undefined)).toBe(true);
    vi.mocked(getAuthRequest).mockResolvedValue({ authRequest: { clientId: "approved-client" } } as any);
    expect(
      await workforceSelfRegistrationDenied({ baseUrl: "https://auth.example.com" }, "another-org", "oidc_request"),
    ).toBe(true);
  });
  it("uses only configured server machine credentials and fails closed on provider/Identity errors", async () => {
    vi.stubEnv("PAYPM_WORKFORCE_IDENTITY_URL", "https://identity.example.com");
    vi.stubEnv("PAYPM_WORKFORCE_IDENTITY_TOKEN_URL", "https://auth.example.com/oauth/v2/token");
    vi.stubEnv("PAYPM_WORKFORCE_IDENTITY_CLIENT_ID", "dedicated-service-client");
    vi.stubEnv("PAYPM_WORKFORCE_IDENTITY_CLIENT_SECRET", "local-test-only");
    vi.stubEnv("PAYPM_WORKFORCE_IDENTITY_SCOPES", "identity.subject.resolve identity.directory.read");
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ access_token: "fixture-machine-token" }), { status: 200 }))
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ personId: "canonical-person", eligible: true, organizationId: "54321" }), {
          status: 200,
        }),
      );
    vi.stubGlobal("fetch", fetcher);
    expect(await workforceEligible(user(), "approved-client", "login")).toBe(true);
    expect(fetcher.mock.calls[1][0].href).toBe(
      "https://identity.example.com/internal/v1/authentication-subjects/workforce-eligibility",
    );
    expect(fetcher.mock.calls[1][1].headers.authorization).toBe("Bearer fixture-machine-token");
    fetcher.mockRejectedValue(new Error("offline"));
    expect(
      await identityWorkforceEligibility.resolve({
        issuer: "https://auth.example.com",
        subject: "12345",
        clientId: "approved-client",
        purpose: "login",
      }),
    ).toBeUndefined();
  });
});
