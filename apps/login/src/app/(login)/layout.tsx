import "@/styles/globals.scss";

import { BackgroundWrapper } from "@/components/background-wrapper";
import { LanguageProvider } from "@/components/language-provider";
import { LanguageSwitcher } from "@/components/language-switcher";
import { Skeleton } from "@/components/skeleton";
import { ThemeProvider } from "@/components/theme-provider";
import { LANGS, getLanguage } from "@/lib/i18n";
import { paypmFont } from "@/lib/paypm-font";
import { getServiceConfig } from "@/lib/service-url";
import { getAllowedLanguages } from "@/lib/zitadel";
import * as Tooltip from "@radix-ui/react-tooltip";
import type { Metadata } from "next";
import { getLocale, getTranslations } from "next-intl/server";
import { headers } from "next/headers";
import React, { Suspense } from "react";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("common");
  return { title: t("title") };
}

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const locale = await getLocale();
  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  let languages = LANGS;
  try {
    const settings = await getAllowedLanguages({ serviceConfig });
    if (settings.allowedLanguages?.length) {
      languages = settings.allowedLanguages
        .filter((code) => LANGS.find((l) => l.code === code))
        .map((code) => getLanguage(code));
    }
  } catch (e) {
    console.error("Failed to load supported languages", e);
  }

  return (
    <html lang={locale} className={paypmFont.className} suppressHydrationWarning>
      <head />
      <body>
        <template
          dangerouslySetInnerHTML={{
            __html: `<!--
THESIS: One shared authentication ceremony, not a promotional split or permission dashboard.
OWN-WORLD: PayPM C3 teal arrival, warm cream work, brass mark, bundled DM Sans, flat 8px controls.
STORY: Recognize PayPM, confirm account, complete the provider's next step, return to the requesting app.
FIRST VIEWPORT: 402×874; compact brand/locale row, left heading, angled seam, labeled field, full Continue, subordinate creation and Back. Wide screens bound the same frame at 520px.
FORM: Owner-pinned C3 arrival seam, selected first composition; key paypm-c3-auth-20260930. No new-world roll.
FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
-->`,
          }}
        />
        <ThemeProvider>
          <Tooltip.Provider>
            <Suspense
              fallback={
                <BackgroundWrapper className="paypm-auth-page">
                  <div className="paypm-auth-container">
                    <Skeleton>
                      <div className="h-40"></div>
                    </Skeleton>
                  </div>
                </BackgroundWrapper>
              }
            >
              <LanguageProvider>
                <BackgroundWrapper className="paypm-auth-page">
                  <div className="paypm-auth-container">
                    <div className="paypm-auth-language">
                      <LanguageSwitcher languages={languages} />
                    </div>
                    <main>{children}</main>
                  </div>
                </BackgroundWrapper>
              </LanguageProvider>
            </Suspense>
          </Tooltip.Provider>
        </ThemeProvider>
      </body>
    </html>
  );
}
