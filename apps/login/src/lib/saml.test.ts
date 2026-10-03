import { beforeEach, describe, expect, it, vi } from "vitest";
import { loginWithSAMLAndSession } from "./saml";
import { sendLoginname } from "./server/loginname";
import { isSessionValid } from "./session";
import { createResponse } from "./zitadel";
vi.mock("./session");
vi.mock("./zitadel");
vi.mock("./server/loginname");
beforeEach(() => vi.clearAllMocks());
describe("SAML session finalization", () => {
  it.each([undefined, {}, { error: "Rejected" }])(
    "denies invalid sessions even if reauthentication returns %j",
    async (response) => {
      vi.mocked(isSessionValid).mockResolvedValue(false);
      vi.mocked(sendLoginname).mockResolvedValue(response as any);
      const result = await loginWithSAMLAndSession({
        serviceConfig: { baseUrl: "https://auth.example.com" },
        samlRequest: "request",
        sessionId: "session",
        sessions: [{ id: "session", factors: { user: { id: "user", loginName: "user@example.com" } } }] as any,
        sessionCookies: [{ id: "session", token: "opaque-token" }] as any,
      });
      expect(result).toEqual({ error: "Session not found or invalid" });
      expect(createResponse).not.toHaveBeenCalled();
    },
  );
});
