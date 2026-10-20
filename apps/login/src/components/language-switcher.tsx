"use client";

import { setLanguageCookie } from "@/lib/cookies";
import { Lang } from "@/lib/i18n";
import { ChevronDownIcon } from "@heroicons/react/24/outline";
import { useLocale, useTranslations } from "next-intl";
import { useRouter } from "next/navigation";
import { useId, useRef, useState, useTransition } from "react";

export function LanguageSwitcher({ languages }: { languages: Lang[] }) {
  const currentLocale = useLocale();
  const t = useTranslations("paypmAuth");
  const router = useRouter();
  const errorId = useId();
  const writing = useRef(false);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const [refreshing, startTransition] = useTransition();
  const currentLanguage = languages.find((language) => language.code === currentLocale) || languages[0];

  async function changeLanguage(code: string) {
    if (writing.current || refreshing || code === currentLocale || !languages.some((language) => language.code === code)) {
      return;
    }
    writing.current = true;
    setBusy(true);
    setFailed(false);
    try {
      await setLanguageCookie(code);
      startTransition(() => router.refresh());
    } catch {
      setFailed(true);
    } finally {
      writing.current = false;
      setBusy(false);
    }
  }

  return (
    <div className="paypm-language" aria-busy={busy || refreshing}>
      <select
        aria-label={t("language")}
        aria-describedby={failed ? errorId : undefined}
        value={currentLanguage?.code || ""}
        disabled={busy || refreshing || languages.length === 0}
        onChange={(event) => void changeLanguage(event.target.value)}
      >
        {languages.map((language) => (
          <option key={language.code} value={language.code} lang={language.code}>
            {language.name}
          </option>
        ))}
      </select>
      <ChevronDownIcon className="paypm-language-chevron" aria-hidden="true" />
      {failed && (
        <p id={errorId} role="alert" className="paypm-language-error">
          {t("languageError")}
        </p>
      )}
    </div>
  );
}
