"use client";

import { ClipboardDocumentCheckIcon, ClipboardIcon } from "@heroicons/react/20/solid";
import copy from "copy-to-clipboard";
import { useTranslations } from "next-intl";
import { useEffect, useState } from "react";

type Props = {
  value: string;
};

export function CopyToClipboard({ value }: Props) {
  const t = useTranslations("paypmAuth");
  const [copied, setCopied] = useState(false);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (copied) {
      const to = setTimeout(setCopied, 1000, false);
      return () => clearTimeout(to);
    }
  }, [copied]);

  return (
    <div className="flex flex-row items-center px-2">
      <button
        id="tooltip-ctc"
        type="button"
        className="paypm-copy-button text-primary-light-500 dark:text-primary-dark-500"
        aria-label={t("copySetupLink")}
        onClick={() => {
          setFailed(false);
          try {
            const successful = copy(value);
            setCopied(successful);
            setFailed(!successful);
          } catch {
            setCopied(false);
            setFailed(true);
          }
        }}
      >
        {!copied ? (
          <ClipboardIcon aria-hidden="true" className="h-5 w-5" />
        ) : (
          <ClipboardDocumentCheckIcon aria-hidden="true" className="h-5 w-5" />
        )}
      </button>
      <span className="sr-only" role="status">
        {copied ? t("setupLinkCopied") : failed ? t("setupLinkCopyError") : ""}
      </span>
    </div>
  );
}
