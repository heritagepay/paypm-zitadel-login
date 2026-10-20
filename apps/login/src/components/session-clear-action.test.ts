import { ResponseCookies } from "next/dist/compiled/@edge-runtime/cookies";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { clearNativeSession } from "./session-clear-action";
const mocks = vi.hoisted(() => ({ clear: vi.fn() }));
vi.mock("@/lib/server/session", () => ({ clearSession: mocks.clear }));
beforeEach(() => vi.resetAllMocks());
describe("native logout server-action boundary", () => {
  it("converts the existing ResponseCookies return to a plain Flight-safe confirmation", async () => {
    const cookies = new ResponseCookies(new Headers());
    const originalReturn = cookies.set("browser-fixture-session", "browser-fixture", { httpOnly: true, sameSite: "lax" });
    expect(Object.getPrototypeOf(originalReturn)).not.toBe(Object.prototype);
    mocks.clear.mockResolvedValue(originalReturn);
    const acknowledgement = await clearNativeSession({ sessionId: "browser-session" });
    expect(mocks.clear).toHaveBeenCalledWith({ sessionId: "browser-session" });
    expect(Object.getPrototypeOf(acknowledgement)).toBe(Object.prototype);
    expect(Reflect.ownKeys(acknowledgement)).toEqual(["cleared"]);
    expect(acknowledgement).toEqual({ cleared: true });
    expect(JSON.parse(JSON.stringify(acknowledgement))).toEqual({ cleared: true });
    expect(JSON.stringify(acknowledgement)).not.toContain("browser-fixture-session");
  });
  it("returns plain non-success for the existing missing-cookie result", async () => {
    mocks.clear.mockResolvedValue(undefined);
    expect(await clearNativeSession({ sessionId: "browser-session" })).toEqual({ cleared: false });
  });
  it("retains the existing rejection for localized client retry", async () => {
    mocks.clear.mockRejectedValue(new Error("opaque provider failure"));
    await expect(clearNativeSession({ sessionId: "browser-session" })).rejects.toThrow("opaque provider failure");
  });
});
