import { createServiceForHost } from "@/lib/service";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { getLoginSettings } from "./zitadel";
vi.mock("@/lib/service", () => ({ createServiceForHost: vi.fn() }));
const getPolicy = vi.fn();
beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(createServiceForHost).mockResolvedValue({ getLoginSettings: getPolicy } as any);
});
describe("current provider login policy", () => {
  it("does not retain a permissive policy after a provider policy change", async () => {
    getPolicy
      .mockResolvedValueOnce({ settings: { forceMfa: false } })
      .mockResolvedValueOnce({ settings: { forceMfa: true } })
      .mockResolvedValueOnce({});
    const command = { serviceConfig: { baseUrl: "https://auth.example.com" }, organization: "ops-org" };
    expect(await getLoginSettings(command)).toMatchObject({ forceMfa: false });
    expect(await getLoginSettings(command)).toMatchObject({ forceMfa: true });
    expect(await getLoginSettings(command)).toBeUndefined();
    expect(getPolicy).toHaveBeenCalledTimes(3);
  });
});
