"use client";

import "@/styles/globals.scss";

import { PaypmBrand } from "@/components/paypm-brand";
import { paypmFont } from "@/lib/paypm-font";
import { useEffect, useState } from "react";
import englishMessages from "../../locales/en.json";
import frenchMessages from "../../locales/fr.json";

type Locale = "en" | "fr";

const messages = {
  en: englishMessages.paypmAuth,
  fr: frenchMessages.paypmAuth,
};

export default function GlobalError({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  const [locale, setLocale] = useState<Locale>("en");

  useEffect(() => {
    setLocale(navigator.language.toLowerCase().startsWith("fr") ? "fr" : "en");
  }, []);

  const copy = messages[locale];

  // The root providers may have failed. This choice only translates the fallback;
  // the server-owned language cookie and authentication context remain intact.
  return (
    // global-error must include html and body tags
    <html lang={locale} className={paypmFont.className} style={{ colorScheme: "light" }}>
      <head>
        <meta name="color-scheme" content="light" />
        <title>{`${copy.unavailableTitle} · PayPM`}</title>
      </head>
      <body>
        <div className="paypm-auth-background">
          <div className="paypm-auth-frame">
            <header className="paypm-auth-arrival">
              <PaypmBrand />
              <div className="paypm-language-fallback">
                <label htmlFor="error-language">{copy.language}</label>
                <select
                  id="error-language"
                  value={locale}
                  onChange={(event) => setLocale(event.target.value === "fr" ? "fr" : "en")}
                >
                  <option value="en" lang="en">
                    English
                  </option>
                  <option value="fr" lang="fr">
                    Français
                  </option>
                </select>
              </div>
            </header>
            <main className="paypm-auth-work">
              <div role="alert">
                <h1>{copy.unavailableTitle}</h1>
                <p>{copy.unavailableDescription}</p>
              </div>
              <button type="button" className="paypm-button" data-variant="Primary" onClick={() => reset()}>
                {copy.tryAgain}
              </button>
            </main>
          </div>
        </div>
      </body>
    </html>
  );
}
