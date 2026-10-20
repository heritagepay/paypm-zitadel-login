"use client";

import { PaypmBrand } from "@/components/paypm-brand";
import { useTranslations } from "next-intl";

type Props = {
  error: Error & { digest?: string };
  reset: () => void;
};

export default function LoginError({ reset }: Props) {
  const t = useTranslations("paypmAuth");

  return (
    <div className="paypm-auth-frame">
      <header className="paypm-auth-arrival">
        <PaypmBrand />
      </header>
      <main className="paypm-auth-work">
        <div role="alert">
          <h1>{t("unavailableTitle")}</h1>
          <p>{t("unavailableDescription")}</p>
        </div>
        <button type="button" className="paypm-button" data-variant="Primary" onClick={() => reset()}>
          {t("tryAgain")}
        </button>
      </main>
    </div>
  );
}
