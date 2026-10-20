import { cleanup, render, screen } from "@testing-library/react";
import { NextIntlClientProvider } from "next-intl";
import { afterEach, describe, expect, it } from "vitest";
import en from "../../locales/en.json";
import fr from "../../locales/fr.json";
import { EMAIL, PASSKEYS, PASSWORD, SMS, TOTP, U2F } from "./auth-methods";

afterEach(cleanup);
describe("native authentication method cards", () => {
  it.each(["en", "fr"] as const)(
    "has localized accessible names, original links and focusable enabled controls in %s",
    (locale) => {
      const t = locale === "fr" ? fr : en;
      const methods = [TOTP, U2F, EMAIL, SMS, PASSKEYS, PASSWORD];
      const labels = [
        t.authenticator.methods.totp,
        t.authenticator.methods.u2f,
        t.authenticator.methods.email,
        t.authenticator.methods.sms,
        t.authenticator.methods.passkeys,
        t.authenticator.methods.password,
      ];
      render(
        <NextIntlClientProvider locale={locale} messages={t} timeZone="UTC">
          {methods.map((method, i) => method(false, `/fixture-${i}`))}
        </NextIntlClientProvider>,
      );
      labels.forEach((label, i) => {
        const link = screen.getByRole("link", { name: label });
        expect(link).toHaveAttribute("href", `/fixture-${i}`);
        expect(link).toHaveClass("paypm-auth-method");
        link.focus();
        expect(link).toHaveFocus();
        expect(link.querySelector("svg")).toHaveAttribute("aria-hidden", "true");
      });
    },
  );
  it.each(["en", "fr"] as const)(
    "keeps configured cards readable, non-actionable and explicitly labeled in %s",
    (locale) => {
      const t = locale === "fr" ? fr : en;
      render(
        <NextIntlClientProvider locale={locale} messages={t} timeZone="UTC">
          {[TOTP, U2F, EMAIL, SMS, PASSKEYS, PASSWORD].map((method, i) => method(true, `/fixture-${i}`))}
        </NextIntlClientProvider>,
      );
      expect(screen.queryByRole("link")).not.toBeInTheDocument();
      expect(screen.getAllByText(t.authenticator.methods.configured)).toHaveLength(6);
      for (const card of screen.getAllByRole("group")) {
        expect(card).toHaveAttribute("aria-disabled", "true");
        expect(card.querySelector(".opacity-50")).toBeNull();
        expect(card).not.toHaveClass("opacity-50");
        expect(card).not.toHaveAttribute("tabindex");
      }
    },
  );
});
