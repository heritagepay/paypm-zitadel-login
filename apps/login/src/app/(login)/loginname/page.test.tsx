import { workforceClientMode, workforcePolicy, workforceRequestClient } from "@/lib/workforce-policy";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Page from "./page";
vi.mock("next/headers", () => ({ headers: vi.fn(() => new Headers()) }));
vi.mock("next-intl/server", () => ({ getTranslations: vi.fn(async () => (key: string) => key) }));
vi.mock("@/lib/service-url", () => ({
  getServiceConfig: () => ({ serviceConfig: { baseUrl: "https://auth.example.test" } }),
}));
vi.mock("@/lib/zitadel", () => ({
  getDefaultOrg: vi.fn(),
  getLoginSettings: vi.fn(async () => ({ allowLocalAuthentication: true })),
  getBrandingSettings: vi.fn(),
  getActiveIdentityProviders: vi.fn(async () => ({ identityProviders: [] })),
}));
vi.mock("@/lib/workforce-policy", () => ({
  workforcePolicy: vi.fn(),
  workforceClientMode: vi.fn(),
  workforceRequestClient: vi.fn(),
}));
vi.mock("@/components/dynamic-theme", () => ({ DynamicTheme: ({ children }: any) => <div>{children}</div> }));
vi.mock("@/components/username-form", () => ({ UsernameForm: () => <div>incumbent identifier</div> }));
vi.mock("@/components/workforce-email-form", () => ({
  WorkforceEmailForm: ({ requestId }: any) => <div>workforce email {requestId}</div>,
}));
vi.mock("@/components/translated", () => ({ Translated: () => null }));
vi.mock("@/components/sign-in-with-idp", () => ({ SignInWithIdp: () => null }));
beforeEach(() => {
  vi.resetAllMocks();
  vi.stubEnv("PAYPM_WORKFORCE_EMAIL_OTP_READY", "true");
  vi.mocked(workforcePolicy).mockReturnValue({
    issuer: "https://auth.example.test",
    organizationId: "12345",
    clientIds: ["registered"],
    emailOtpReady: true,
  });
  vi.mocked(workforceRequestClient).mockResolvedValue("registered");
  vi.mocked(workforceClientMode).mockReturnValue("limited");
});
afterEach(() => {
  cleanup();
  vi.unstubAllEnvs();
});
async function mount() {
  render(await Page({ searchParams: Promise.resolve({ requestId: "oidc_exact" }) }));
}
describe("server-owned workforce entry category", () => {
  it("shows OTP for the registered workforce OIDC client only", async () => {
    await mount();
    expect(screen.getByText("workforce email oidc_exact")).toBeInTheDocument();
    expect(screen.queryByText("incumbent identifier")).toBeNull();
  });
  it("denies missing per-client policy instead of falling through to the incumbent credential flow", async () => {
    vi.mocked(workforceClientMode).mockReturnValue(undefined);
    await mount();
    expect(screen.getByText("unavailable")).toBeInTheDocument();
    expect(screen.queryByText("incumbent identifier")).toBeNull();
  });
  it("denies invalid workforce registry while its OTP readiness is enabled", async () => {
    vi.mocked(workforcePolicy).mockReturnValue(undefined);
    await mount();
    expect(screen.getByText("unavailable")).toBeInTheDocument();
    expect(screen.queryByText("incumbent identifier")).toBeNull();
  });
  it("preserves the incumbent entry while readiness is off and for unrelated clients", async () => {
    vi.stubEnv("PAYPM_WORKFORCE_EMAIL_OTP_READY", "false");
    vi.mocked(workforcePolicy).mockReturnValue({ ...workforcePolicy()!, emailOtpReady: false });
    await mount();
    expect(screen.getByText("incumbent identifier")).toBeInTheDocument();
    cleanup();
    vi.stubEnv("PAYPM_WORKFORCE_EMAIL_OTP_READY", "true");
    vi.mocked(workforcePolicy).mockReturnValue({ ...workforcePolicy()!, emailOtpReady: true });
    vi.mocked(workforceRequestClient).mockResolvedValue(undefined);
    await mount();
    expect(screen.getByText("incumbent identifier")).toBeInTheDocument();
  });
});
