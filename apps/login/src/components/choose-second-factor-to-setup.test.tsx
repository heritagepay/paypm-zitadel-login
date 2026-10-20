import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { create } from "@zitadel/client";
import { LoginSettingsSchema, SecondFactorType } from "@zitadel/proto/zitadel/settings/v2/login_settings_pb";
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { NextIntlClientProvider } from "next-intl";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import en from "../../locales/en.json";
import fr from "../../locales/fr.json";
import { ChooseSecondFactorToSetup } from "./choose-second-factor-to-setup";

const mocks = vi.hoisted(() => ({ skip: vi.fn(), push: vi.fn() }));
vi.mock("@/lib/server/session", () => ({ skipMFAAndContinueWithNextUrl: mocks.skip }));
vi.mock("next/navigation", () => ({ useRouter: () => ({ push: mocks.push }) }));
vi.mock("./auto-submit-form", () => ({ AutoSubmitForm: () => <div data-testid="saml-continuation" /> }));

const props = {
  userId: "fixture-user",
  loginName: "fixture@example.invalid",
  sessionId: "fixture-session",
  requestId: "fixture-request",
  organization: "fixture-organization",
  loginSettings: create(LoginSettingsSchema, {
    secondFactors: [SecondFactorType.OTP, SecondFactorType.U2F, SecondFactorType.OTP_EMAIL, SecondFactorType.OTP_SMS],
  }),
  userMethods: [AuthenticationMethodType.TOTP],
  checkAfter: true,
  phoneVerified: false,
  emailVerified: true,
  force: false,
};
const view = (locale: "en" | "fr" = "en", force = false) => (
  <NextIntlClientProvider locale={locale} messages={locale === "fr" ? fr : en} timeZone="UTC">
    <ChooseSecondFactorToSetup {...props} force={force} />
  </NextIntlClientProvider>
);
const deferred = () => {
  let resolve!: (value: unknown) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
};
beforeEach(() => vi.resetAllMocks());
afterEach(cleanup);

describe("MFA Skip control preserves the existing ceremony", () => {
  it.each(["en", "fr"] as const)(
    "guards held requests and remains pending through confirmed continuation in %s",
    async (locale) => {
      const held = deferred();
      mocks.skip.mockReturnValue(held.promise);
      render(view(locale));
      const t = locale === "fr" ? fr : en;
      const button = screen.getByRole("button", { name: t.mfa.set.skip });
      fireEvent.click(button);
      fireEvent.click(button);
      fireEvent.keyDown(button, { key: "Enter" });
      expect(button).toBeDisabled();
      expect(button).toHaveAttribute("aria-busy", "true");
      expect(button).toHaveTextContent(t.mfa.set.pending);
      expect(mocks.skip).toHaveBeenCalledTimes(1);
      expect(mocks.skip).toHaveBeenCalledWith({
        userId: props.userId,
        loginName: props.loginName,
        sessionId: props.sessionId,
        requestId: props.requestId,
        organization: props.organization,
      });
      expect(mocks.push).not.toHaveBeenCalled();
      await act(async () => held.resolve({ redirect: "/fixture-next" }));
      expect(mocks.push).toHaveBeenCalledWith("/fixture-next");
      fireEvent.click(button);
      expect(mocks.skip).toHaveBeenCalledTimes(1);
      expect(button).toBeDisabled();
    },
  );

  it.each(["en", "fr"] as const)("uses localized failure, releases the guard and permits retry in %s", async (locale) => {
    mocks.skip.mockRejectedValueOnce(new Error("opaque provider failure"));
    render(view(locale));
    const t = locale === "fr" ? fr : en;
    const button = screen.getByRole("button");
    fireEvent.click(button);
    expect(await screen.findByRole("alert")).toHaveTextContent(t.mfa.set.error);
    expect(button).toHaveAccessibleDescription(t.mfa.set.error);
    expect(button).toBeEnabled();
    expect(screen.queryByText("opaque provider failure")).not.toBeInTheDocument();
    mocks.skip.mockResolvedValueOnce({ redirect: "/fixture-retry" });
    fireEvent.click(button);
    await waitFor(() => expect(mocks.push).toHaveBeenCalledWith("/fixture-retry"));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it.each([undefined, { error: "opaque provider failure" }, { redirect: "javascript:fixture" }])(
    "retains the page and retry for unconfirmed or rejected continuation %j",
    async (response) => {
      mocks.skip.mockResolvedValue(response);
      const warning = vi.spyOn(console, "warn").mockImplementation(() => {});
      render(view());
      fireEvent.click(screen.getByRole("button"));
      expect(await screen.findByRole("alert")).toHaveTextContent(en.mfa.set.error);
      expect(screen.getByRole("button")).toBeEnabled();
      expect(mocks.push).not.toHaveBeenCalled();
      warning.mockRestore();
    },
  );

  it("keeps the existing SAML continuation and prevents a repeat until unmount", async () => {
    mocks.skip.mockResolvedValue({ samlData: { url: "https://fixture.invalid", fields: { fixture: "value" } } });
    render(view());
    fireEvent.click(screen.getByRole("button"));
    expect(await screen.findByTestId("saml-continuation")).toBeInTheDocument();
    expect(screen.getByRole("button")).toBeDisabled();
    expect(mocks.push).not.toHaveBeenCalled();
  });

  it.each(["resolve", "reject"] as const)(
    "ignores late %s after unmount and starts a fresh enabled control",
    async (outcome) => {
      const held = deferred();
      mocks.skip.mockReturnValue(held.promise);
      const { unmount } = render(view());
      fireEvent.click(screen.getByRole("button"));
      unmount();
      await act(async () =>
        outcome === "resolve" ? held.resolve({ redirect: "/fixture-late" }) : held.reject(new Error("late failure")),
      );
      expect(mocks.push).not.toHaveBeenCalled();
      render(view());
      expect(screen.getByRole("button", { name: en.mfa.set.skip })).toBeEnabled();
    },
  );

  it("denies Skip for required MFA and preserves verified method availability and exact links", () => {
    render(view("fr", true));
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    expect(mocks.skip).not.toHaveBeenCalled();
    expect(screen.queryByRole("link", { name: fr.authenticator.methods.sms })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: fr.authenticator.methods.totp })).not.toBeInTheDocument();
    expect(screen.getByText(fr.authenticator.methods.totp).closest('[aria-disabled="true"]')).toBeInTheDocument();
    expect(screen.getByRole("link", { name: fr.authenticator.methods.email })).toHaveAttribute(
      "href",
      "/otp/email/set?loginName=fixture%40example.invalid&sessionId=fixture-session&requestId=fixture-request&organization=fixture-organization&checkAfter=true",
    );
  });
});
