import type { Browser, Page } from "@playwright/test";
import tailwind from "@tailwindcss/postcss";
import { NextIntlClientProvider } from "next-intl";
import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import postcss from "postcss";
import { renderToStaticMarkup } from "react-dom/server";
import * as sass from "sass";
import { Button, ButtonVariants } from "../../src/components/button";
import { EMAIL, PASSKEYS, PASSWORD, SMS, TOTP, U2F } from "../../src/components/auth-methods";
import { CopyToClipboard } from "../../src/components/copy-to-clipboard";
import { BaseButton } from "../../src/components/idps/base-button";
import { PaypmBrand } from "../../src/components/paypm-brand";
import { Spinner } from "../../src/components/spinner";

// Source preview only. Real shared components are SSR rendered; locale/session
// anatomy projects current owner classes. No provider route or handler mounts.
async function main() {
  if (!process.env.PLAYWRIGHT_MODULE)
    throw new Error("Set PLAYWRIGHT_MODULE to an existing compatible playwright/index.mjs");
  const { chromium } = await import(pathToFileURL(resolve(process.env.PLAYWRIGHT_MODULE)).href);
  const output = resolve(process.env.LOGIN_CONTROL_OUTPUT ?? "test-results/control-affordance");
  await mkdir(output, { recursive: true });
  const compiled = sass.compile("src/styles/globals.scss", { loadPaths: ["node_modules", "../../node_modules"] });
  const stylesheet = await postcss([tailwind({ base: process.cwd() })]).process(compiled.css, {
    from: resolve("src/styles/globals.scss"),
  });
  const font = (await readFile("src/assets/fonts/DMSans/DMSans-Regular.ttf")).toString("base64");
  const browser: Browser = await chromium.launch({ headless: true });
  const page: Page = await browser.newPage({ reducedMotion: "reduce" });
  let blockedRequests = 0;
  await page.route("**/*", (route) => {
    blockedRequests += 1;
    return route.abort();
  });
  const reports: unknown[] = [];

  try {
    for (const locale of ["en", "fr"]) {
      const t = JSON.parse(await readFile(`locales/${locale}.json`, "utf8"));
      const body = renderToStaticMarkup(
        <NextIntlClientProvider locale={locale} messages={t} timeZone="UTC">
          <div className="paypm-auth-page">
            <div className="paypm-auth-container">
              <div className="paypm-auth-language">
                <div className="paypm-language">
                  <select aria-label={t.paypmAuth.language} defaultValue={locale}>
                    <option value="en">English</option>
                    <option value="fr">Français</option>
                  </select>
                  <span className="paypm-language-chevron" aria-hidden="true">
                    ⌄
                  </span>
                </div>
              </div>
              <main>
                <section className="paypm-auth-frame">
                  <header className="paypm-auth-arrival">
                    <PaypmBrand />
                    <div className="paypm-auth-title">
                      <h1>{t.loginname.title}</h1>
                      <p>{t.loginname.description}</p>
                    </div>
                  </header>
                  <div className="paypm-auth-work">
                    <button type="button" data-testid="reset-button">
                      {t.password.verify.resetPassword}
                    </button>
                    <button type="button" className="paypm-mfa-skip" data-testid="skip-button">
                      {t.mfa.set.skip}
                    </button>
                    <button type="button" className="paypm-mfa-skip" disabled aria-busy="true">
                      <Spinner className="h-5 w-5" />
                      {t.mfa.set.pending}
                    </button>
                    <div className="grid w-full grid-cols-1 gap-5 pt-4">
                      {[TOTP, U2F, EMAIL, SMS, PASSKEYS, PASSWORD].map((method, index) => (
                        <div key={index}>
                          {method(false, `/fixture-method-${index}`)}
                          {method(true, `/fixture-configured-${index}`)}
                        </div>
                      ))}
                    </div>
                    <button type="button" data-testid="resend-button">
                      {t.otp.verify.resendCode}
                    </button>
                    <CopyToClipboard value="browser-fixture://setup" />
                    <button type="button" className="paypm-button" data-variant="Primary">
                      {t.paypmAuth.tryAgain}
                    </button>
                    <BaseButton>{t.idp.signInWithGoogle}</BaseButton>
                    <button
                      className="paypm-session-clear"
                      type="button"
                      aria-label={`${t.logout.clear}: fixture-long-account@example.invalid`}
                    >
                      <div className="pr-4" aria-hidden="true">
                        <span style={{ display: "inline-block", width: 40, height: 40 }}>A</span>
                      </div>
                      <div className="flex flex-col items-start overflow-hidden">
                        <span>Browser preview account</span>
                        <span className="text-xs opacity-80">fixture-long-account@example.invalid</span>
                      </div>
                      <span className="flex-grow" />
                      <div className="relative flex flex-row items-center">
                        <span className="paypm-clear-label">{t.logout.clear}</span>
                      </div>
                    </button>
                    <form>
                      <label className="paypm-field" htmlFor="identifier">
                        {t.loginname.labels.loginname}
                      </label>
                      <input id="identifier" className="paypm-input w-full" value="" readOnly />
                      <div className="paypm-identifier-submit">
                        <Button className="w-full">{t.loginname.submit}</Button>
                      </div>
                      <div className="paypm-identifier-register">
                        <Button variant={ButtonVariants.Secondary} className="w-full">
                          {t.loginname.register}
                        </Button>
                      </div>
                      <div className="paypm-identifier-return">
                        <Button variant={ButtonVariants.Secondary}>{t.common.back}</Button>
                      </div>
                    </form>
                    <div className="paypm-session">
                      <button className="paypm-session-select">
                        <div className="flex flex-col overflow-hidden">
                          <span>Browser preview account</span>
                          <span className="text-xs opacity-80">fixture-long-account@example.invalid</span>
                        </div>
                      </button>
                      <button className="paypm-session-remove" aria-label={t.paypmAuth.removeAccount}>
                        ×
                      </button>
                    </div>
                    <form aria-busy="true">
                      <Button disabled className="w-full">
                        <Spinner className="h-5 w-5" />
                        {t.loginname.submit}
                      </Button>
                      <Button disabled variant={ButtonVariants.Secondary} className="w-full">
                        {t.common.back}
                      </Button>
                    </form>
                    <div className="paypm-session" aria-busy="true">
                      <button className="paypm-session-select" disabled aria-busy="true">
                        <span>Browser preview account</span>
                        <Spinner className="h-5 w-5" />
                      </button>
                      <button className="paypm-session-remove" disabled aria-label={t.paypmAuth.removeAccount}>
                        ×
                      </button>
                    </div>
                    <div className="paypm-language" aria-busy="true" style={{ background: "var(--paypm-teal)" }}>
                      <select disabled aria-label={t.paypmAuth.language} defaultValue={locale}>
                        <option value="en">English</option>
                        <option value="fr">Français</option>
                      </select>
                    </div>
                  </div>
                </section>
              </main>
            </div>
          </div>
        </NextIntlClientProvider>,
      );
      for (const width of [320, 390, 768, 1280])
        for (const scale of [100, 200]) {
          await page.setViewportSize({ width, height: 1000 });
          await page.setContent(
            `<html lang="${locale}"><head><style>${stylesheet.css}@font-face{font-family:PreviewDM;src:url(data:font/ttf;base64,${font})}html{font-family:PreviewDM,Arial,sans-serif}</style></head><body>${body}</body></html>`,
          );
          await page.evaluate(() => document.fonts.ready);
          if (scale === 200)
            await page.evaluate(() => {
              const nodes = Array.from(document.querySelectorAll<HTMLElement>("body *")).filter(
                (node) =>
                  node.getClientRects().length &&
                  !node.closest('[aria-hidden="true"]') &&
                  (node.matches("input,select,button") ||
                    Array.from(node.childNodes).some(
                      (child) => child.nodeType === Node.TEXT_NODE && child.textContent?.trim(),
                    )),
              );
              const sizes = nodes.map((node) => [node, parseFloat(getComputedStyle(node).fontSize)] as const);
              for (const [node, size] of sizes) node.style.fontSize = `${size * 2}px`;
            });
          const primary = page.locator("form:not([aria-busy]) .paypm-button--primary");
          await primary.focus();
          const measure = await page.evaluate(() => {
            const channels = (color: string) =>
              color.startsWith("color(srgb")
                ? color
                    .match(/[\d.]+/g)!
                    .slice(0, 3)
                    .map(Number)
                : color
                    .match(/[\d.]+/g)!
                    .slice(0, 3)
                    .map((v) => Number(v) / 255);
            const luminance = (color: string) =>
              channels(color)
                .map((c) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4))
                .reduce((sum, c, i) => sum + c * [0.2126, 0.7152, 0.0722][i], 0);
            const ratio = (a: string, b: string) =>
              (Math.max(luminance(a), luminance(b)) + 0.05) / (Math.min(luminance(a), luminance(b)) + 0.05);
            const background = (node: Element | null): string => {
              while (node && getComputedStyle(node).backgroundColor === "rgba(0, 0, 0, 0)") node = node.parentElement;
              return node ? getComputedStyle(node).backgroundColor : "rgb(250,246,238)";
            };
            return {
              content: document.documentElement.scrollWidth,
              controls: Array.from(document.querySelectorAll<HTMLElement>("button,select,.paypm-auth-method")).map(
                (node) => {
                  const s = getComputedStyle(node),
                    b = node.getBoundingClientRect();
                  return {
                    label: node.getAttribute("aria-label") || node.textContent?.trim(),
                    width: b.width,
                    height: b.height,
                    left: b.left,
                    right: b.right,
                    clipped: node.scrollHeight > node.clientHeight + 1,
                    disabled: node.matches(":disabled,[aria-disabled=true]"),
                    opacity: s.opacity,
                    focus: node.matches(":focus-visible"),
                    focusRatio: ratio(s.outlineColor, background(node.parentElement)),
                    edgeRatio:
                      node.classList.contains("paypm-button--secondary") ||
                      node.tagName === "SELECT" ||
                      !node.classList.contains("paypm-button")
                        ? ratio(s.borderTopColor, background(node))
                        : null,
                  };
                },
              ),
            };
          });
          assert.ok(measure.content <= width + 1, `${locale}/${width}/${scale}: page overflow`);
          for (const c of measure.controls) {
            assert.ok(
              c.width >= 44 && c.height >= 44 && c.left >= -1 && c.right <= width + 1 && !c.clipped,
              `${locale}/${width}/${scale}: ${c.label} must fit its44px target`,
            );
            if (c.disabled) assert.equal(c.opacity, "1", "Pending/disabled commands must not fade twice");
            if (c.focus) assert.ok(c.focusRatio >= 3, "Focus must remain visible on its surrounding surface");
            if (c.edgeRatio !== null && !c.disabled)
              assert.ok(c.edgeRatio >= 3, `${c.label}: enabled secondary/select boundary ${c.edgeRatio} must reach3:1`);
          }
          assert.equal(
            await page.locator("form[aria-busy] svg").evaluate((node) => getComputedStyle(node).animationName),
            "none",
          );
          assert.equal(
            await page.locator("form[aria-busy] svg path:last-child").evaluate((node) => getComputedStyle(node).fill),
            "rgb(255, 255, 255)",
            "Static pending arc must contrast with the primary fill",
          );
          assert.equal(await page.locator(".paypm-mfa-skip[aria-busy] svg").evaluate((node) => getComputedStyle(node).animationName), "none");
          assert.equal(await page.locator(".paypm-mfa-skip[aria-busy] svg path:last-child").evaluate((node) => getComputedStyle(node).fill),
            await page.locator(".paypm-mfa-skip[aria-busy]").evaluate((node) => getComputedStyle(node).color),
            "Static MFA pending arc must inherit its readable foreground");
          assert.equal(await page.locator(".paypm-auth-method[aria-disabled=true]").count(), 6);
          for (const card of await page.locator(".paypm-auth-method[aria-disabled=true]").all()) {
            assert.equal(await card.evaluate((node) => [node, ...Array.from(node.querySelectorAll("span"))].every((child) => getComputedStyle(child).opacity === "1")), true,
              "Configured method labels must remain opaque without nested fading");
            assert.equal(await card.getAttribute("href"), null, "Configured methods must not become actions");
          }
          for (const card of await page.locator("a.paypm-auth-method").all()) {
            await page.keyboard.press("Tab");
            await card.focus();
            assert.equal(await card.evaluate((node) => node.matches(":focus-visible") && getComputedStyle(node).outlineStyle === "solid" && parseFloat(getComputedStyle(node).outlineWidth) >= 3), true,
              "Every available method must expose the inherited keyboard focus");
          }
          await page.screenshot({ path: `${output}/${locale}-${width}-${scale}.png`, fullPage: true });
          await page.locator("a.paypm-auth-method").first().scrollIntoViewIfNeeded();
          await page.screenshot({ path: `${output}/${locale}-${width}-${scale}-mfa.png` });
          for (const selector of [
            "form:not([aria-busy]) .paypm-button--primary",
            ".paypm-identifier-register .paypm-button--secondary",
            ".paypm-identifier-return .paypm-button--secondary",
            ".paypm-session:not([aria-busy]) .paypm-session-select",
            ".paypm-session:not([aria-busy]) .paypm-session-remove",
            "[data-testid=reset-button]",
            "[data-testid=skip-button]",
            "[data-testid=resend-button]",
            ".paypm-copy-button",
            ".paypm-idp-button",
            ".paypm-button[data-variant=Primary]",
            ".paypm-session-clear",
            ...Array.from({length: 6}, (_, index) => `a[href='/fixture-method-${index}']`),
          ]) {
            const control = page.locator(selector);
            await control.scrollIntoViewIfNeeded();
            const b = await control.boundingBox();
            assert.ok(b);
            const point = { x: b.x + 4, y: b.y + b.height - 4 };
            assert.equal(
              await control.evaluate((node, p) => node.contains(document.elementFromPoint(p.x, p.y)), point),
              true,
              "Visible lower padding must hit the same native control",
            );
            await page.mouse.move(point.x, point.y);
            const restingShadow = await control.evaluate((node) => getComputedStyle(node).boxShadow);
            assert.ok(!restingShadow.includes("inset"), "Enabled command must start with its resting appearance");
            await page.mouse.down();
            const pressedShadow = await control.evaluate((node) => getComputedStyle(node).boxShadow);
            assert.ok(
              pressedShadow.includes("inset") && pressedShadow !== restingShadow,
              `${selector}: press must change immediately to the visible inset appearance`,
            );
            await page.mouse.move(0, 0);
            await page.mouse.up();
          }
          reports.push({ locale, width, scale, measure, staticPress: true, paddingHit: true, providerRequests: 0 });
        }
    }
    console.log(
      JSON.stringify({ sourcePreviewStates: reports.length, blockedRequests, providerRequests: 0, sourceOnly: true }),
    );
  } finally {
    await writeFile(`${output}/controls.json`, JSON.stringify(reports, null, 2));
    await browser.close();
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
