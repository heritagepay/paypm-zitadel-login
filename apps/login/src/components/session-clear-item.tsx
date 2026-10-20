"use client";

import { timestampDate } from "@zitadel/client";
import { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import moment from "moment";
import { useLocale, useTranslations } from "next-intl";
import { useEffect, useId, useRef, useState } from "react";
import { Alert } from "./alert";
import { Avatar } from "./avatar";
import { clearNativeSession } from "./session-clear-action";
import { isSessionValid } from "./session-item";
import { Spinner } from "./spinner";
import { Translated } from "./translated";

export function SessionClearItem({ session, reload }: { session: Session; reload: () => void }) {
  const currentLocale = useLocale();
  const t = useTranslations("paypmAuth");
  const logout = useTranslations("logout");
  moment.locale(currentLocale === "zh" ? "zh-cn" : currentLocale);

  const [loading, setLoading] = useState(false);
  const [hasError, setHasError] = useState(false);
  const inFlight = useRef(false);
  const mounted = useRef(true);
  const errorId = useId();

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  async function clearSessionId() {
    if (inFlight.current || !mounted.current) return;
    inFlight.current = true;
    setLoading(true);
    setHasError(false);
    try {
      const response = await clearNativeSession({ sessionId: session.id });
      if (!mounted.current) return;
      if (response?.cleared !== true) {
        setHasError(true);
        return;
      }
      reload();
    } catch {
      if (mounted.current) setHasError(true);
    } finally {
      inFlight.current = false;
      if (mounted.current) setLoading(false);
    }
  }

  const { valid, verifiedAt } = isSessionValid(session);

  return (
    <div>
      <button
        type="button"
        onClick={() => void clearSessionId()}
        disabled={loading}
        aria-busy={loading}
        aria-label={`${logout("clear")}: ${session.factors?.user?.loginName ?? ""}`}
        aria-describedby={hasError ? errorId : undefined}
        className="paypm-session-clear group border-divider-light bg-background-light-400 dark:bg-background-dark-400 flex flex-row items-center rounded-md border px-4 py-2 transition-all dark:hover:bg-white/10"
      >
        <div className="pr-4" aria-hidden="true">
          <Avatar
            size="small"
            loginName={session.factors?.user?.loginName as string}
            name={session.factors?.user?.displayName ?? ""}
          />
        </div>

        <div className="flex flex-col items-start overflow-hidden">
          <span className="">{session.factors?.user?.displayName}</span>
          <span className="text-xs text-ellipsis opacity-80">{session.factors?.user?.loginName}</span>
          {valid ? (
            <span className="text-xs text-ellipsis opacity-80">
              {verifiedAt && (
                <Translated
                  i18nKey="verifiedAt"
                  namespace="logout"
                  data={{ time: moment(timestampDate(verifiedAt)).fromNow() }}
                />
              )}
            </span>
          ) : (
            verifiedAt && (
              <span className="text-xs text-ellipsis opacity-80">
                <Translated i18nKey="expired" namespace="accounts" />{" "}
                {session.expirationDate && moment(timestampDate(session.expirationDate)).fromNow()}
              </span>
            )
          )}
        </div>

        <span className="flex-grow"></span>
        <div className="relative flex flex-row items-center">
          <span className="paypm-clear-label">
            <Translated i18nKey="clear" namespace="logout" />
          </span>

          {valid ? (
            <div className="absolute right-0 mx-2 h-2 w-2 transform rounded-full bg-green-500 transition-all"></div>
          ) : (
            <div className="absolute right-0 mx-2 h-2 w-2 transform rounded-full bg-red-500 transition-all"></div>
          )}
        </div>
        {loading && <Spinner className="h-5 w-5 flex-shrink-0" />}
      </button>
      {hasError && (
        <div id={errorId} className="mt-2">
          <Alert>{t("sessionError")}</Alert>
        </div>
      )}
    </div>
  );
}
