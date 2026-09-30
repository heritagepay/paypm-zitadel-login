import { createServiceForHost } from "@/lib/service";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { getHostedLoginTranslation } from "./zitadel";

vi.mock("@/lib/service", () => ({ createServiceForHost: vi.fn() }));

describe("hosted login translations", () => {
  const getTranslation = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(createServiceForHost).mockResolvedValue({ getHostedLoginTranslation: getTranslation } as any);
  });

  it("requests only explicit instance translations, not the system fallback", async () => {
    getTranslation.mockResolvedValue({ translations: undefined });

    const translations = await getHostedLoginTranslation({
      serviceConfig: { baseUrl: "https://example.test", instanceHost: "instance-fr-test" },
      locale: "fr",
    });

    expect(getTranslation).toHaveBeenCalledWith(
      { level: { case: "instance", value: true }, locale: "fr", ignoreInheritance: true },
      {},
    );
    expect(translations).toEqual({});
  });

  it("keeps organization overrides at their own level", async () => {
    getTranslation.mockResolvedValue({ translations: { loginname: { title: "Bienvenue chez nous" } } });

    const translations = await getHostedLoginTranslation({
      serviceConfig: { baseUrl: "https://example.test", instanceHost: "organization-fr-test" },
      locale: "fr",
      organization: "org-1",
    });

    expect(getTranslation).toHaveBeenCalledWith(
      { level: { case: "organizationId", value: "org-1" }, locale: "fr", ignoreInheritance: true },
      {},
    );
    expect(translations).toEqual({ loginname: { title: "Bienvenue chez nous" } });
  });
});
