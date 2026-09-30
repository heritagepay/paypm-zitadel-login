import { getServiceConfig } from "@/lib/service-url";
import { getAllowedLanguages, getHostedLoginTranslation } from "@/lib/zitadel";
import { cookies, headers } from "next/headers";
import { beforeEach, describe, expect, it, vi } from "vitest";
import config from "./request";

vi.mock("next-intl/server", () => ({ getRequestConfig: (callback: unknown) => callback }));
vi.mock("next/headers", () => ({ cookies: vi.fn(), headers: vi.fn() }));
vi.mock("@/lib/service-url", () => ({ getServiceConfig: vi.fn() }));
vi.mock("@/lib/zitadel", () => ({ getAllowedLanguages: vi.fn(), getHostedLoginTranslation: vi.fn() }));

const getConfig = config as unknown as () => Promise<{ locale: string; messages: { loginname: { title: string } } }>;

describe("Login V2 message precedence", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(cookies).mockResolvedValue({ get: () => ({ value: "fr" }) } as any);
    vi.mocked(headers).mockResolvedValue({ get: () => null } as any);
    vi.mocked(getServiceConfig).mockReturnValue({ serviceConfig: { baseUrl: "https://example.test" } });
    vi.mocked(getAllowedLanguages).mockResolvedValue({ allowedLanguages: ["en", "fr"], defaultLanguage: "en" } as any);
    vi.mocked(getHostedLoginTranslation).mockResolvedValue({});
  });

  it("preserves bundled French when no explicit custom translation exists", async () => {
    const result = await getConfig();

    expect(result.locale).toBe("fr");
    expect(result.messages.loginname.title).toBe("Bienvenue!");
    expect(getHostedLoginTranslation).toHaveBeenCalledWith({
      serviceConfig: { baseUrl: "https://example.test" },
      locale: "fr",
      organization: undefined,
    });
  });

  it("applies instance and then organization customizations", async () => {
    vi.mocked(headers).mockResolvedValue({
      get: (name: string) => (name === "x-zitadel-i18n-organization" ? "org-1" : null),
    } as any);
    vi.mocked(getHostedLoginTranslation)
      .mockResolvedValueOnce({ loginname: { title: "Instance title" } })
      .mockResolvedValueOnce({ loginname: { title: "Organization title" } });

    const result = await getConfig();

    expect(result.messages.loginname.title).toBe("Organization title");
    expect(getHostedLoginTranslation).toHaveBeenCalledTimes(2);
  });
});
