"use client";

import { visibleLoginName } from "@/lib/visible-login-name";
import { handleServerActionResponse } from "@/lib/client-utils";
import { sendLoginname } from "@/lib/server/loginname";
import { continueWithSession, ContinueWithSessionCommand } from "@/lib/server/session";
import { XCircleIcon } from "@heroicons/react/24/outline";
import * as Tooltip from "@radix-ui/react-tooltip";
import { Timestamp, timestampDate } from "@zitadel/client";
import { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import moment from "moment";
import { useLocale, useTranslations } from "next-intl";
import { useRouter } from "next/navigation";
import { useId, useRef, useState } from "react";
import { Alert } from "./alert";
import { AutoSubmitForm } from "./auto-submit-form";
import { Avatar } from "./avatar";
import { clearNativeSession } from "./session-clear-action";
import { Spinner } from "./spinner";
import { Translated } from "./translated";

export function isSessionValid(session: Partial<Session>): {
  valid: boolean;
  verifiedAt?: Timestamp;
} {
  const validPassword = session?.factors?.password?.verifiedAt;
  const validPasskey = session?.factors?.webAuthN?.verifiedAt;
  const validIDP = session?.factors?.intent?.verifiedAt;

  const stillValid = session.expirationDate ? timestampDate(session.expirationDate) > new Date() : true;

  const verifiedAt = validPassword || validPasskey || validIDP;
  const valid = !!((validPassword || validPasskey || validIDP) && stillValid);

  return { valid, verifiedAt };
}

type Props = {
  session: Session;
  reload: () => void;
  requestId?: string;
  disabled?: boolean;
  onActionStart?: () => boolean;
  onActionEnd?: () => void;
};

export function SessionItem({ session, reload, requestId, disabled, onActionStart, onActionEnd }: Props) {
  const currentLocale = useLocale();
  moment.locale(currentLocale === "zh" ? "zh-cn" : currentLocale);
  const t = useTranslations("paypmAuth");

  const [loading, setLoading] = useState<"select" | "remove" | null>(null);
  const actionInFlight = useRef(false);
  const [hasError, setHasError] = useState(false);
  const errorId = useId();
  const { valid, verifiedAt } = isSessionValid(session);
  const [samlData, setSamlData] = useState<{ url: string; fields: Record<string, string> } | null>(null);
  const router = useRouter();
  const busy = !!loading || !!disabled;

  async function runAction(action: "select" | "remove", operation: () => Promise<void>) {
    if (actionInFlight.current || disabled || onActionStart?.() === false) {
      return;
    }

    actionInFlight.current = true;
    setLoading(action);
    setHasError(false);
    try {
      await operation();
    } catch {
      setHasError(true);
    } finally {
      actionInFlight.current = false;
      setLoading(null);
      onActionEnd?.();
    }
  }

  function selectSession() {
    return runAction("select", async () => {
      const user = session.factors?.user;
      if (!user) {
        setHasError(true);
        return;
      }

      let response;
      if (isSessionValid(session).valid) {
        const sessionPayload: ContinueWithSessionCommand = {
          ...session,
          ...(requestId ? { requestId } : {}),
        };
        response = await continueWithSession(sessionPayload);
      } else {
        response = await sendLoginname({
          loginName: user.loginName,
          organization: user.organizationId,
          requestId,
        });
      }

      if (!handleServerActionResponse(response, router, setSamlData, () => setHasError(true))) {
        setHasError(true);
      }
    });
  }

  function removeSession() {
    return runAction("remove", async () => {
      const response = await clearNativeSession({ sessionId: session.id });
      if (response?.cleared !== true) {
        setHasError(true);
        return;
      }
      reload();
    });
  }

  return (
    <div>
      {samlData && <AutoSubmitForm url={samlData.url} fields={samlData.fields} />}
      <div className="paypm-session" aria-busy={!!loading}>
        <Tooltip.Root delayDuration={300}>
          <Tooltip.Trigger asChild>
            <button
              type="button"
              onClick={() => selectSession()}
              disabled={busy}
              aria-busy={loading === "select"}
              aria-describedby={hasError ? errorId : undefined}
              className="paypm-session-select group flex min-w-0 flex-grow flex-row items-center px-4 py-2 text-left"
            >
              <div className="pr-4" aria-hidden="true">
                <Avatar
                  size="small"
                  loginName={session.factors?.user?.loginName ?? ""}
                  name={session.factors?.user?.displayName ?? ""}
                />
              </div>

              <div className="flex flex-col items-start overflow-hidden">
                <span>{session.factors?.user?.displayName}</span>
                {visibleLoginName(session.factors?.user?.loginName) && (
                  <span className="text-xs text-ellipsis opacity-80">{visibleLoginName(session.factors?.user?.loginName)}</span>
                )}
                {valid ? (
                  <span className="text-xs text-ellipsis opacity-80">
                    <Translated i18nKey="verified" namespace="accounts" />{" "}
                    {verifiedAt && moment(timestampDate(verifiedAt)).fromNow()}
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
              <span className="flex-grow" />
              <span
                aria-hidden="true"
                className={`mx-2 h-2 w-2 flex-shrink-0 rounded-full ${valid ? "bg-green-500" : "bg-red-500"}`}
              />
              {loading === "select" && <Spinner className="ml-2 h-4 w-4 flex-shrink-0" />}
            </button>
          </Tooltip.Trigger>
          {valid && session.expirationDate && (
            <Tooltip.Portal>
              <Tooltip.Content
                className="bg-background-light-500 dark:bg-background-dark-500 z-50 rounded-md border px-3 py-2 text-xs text-black shadow-xl select-none dark:border-white/20 dark:text-white"
                sideOffset={5}
              >
                {t("expires", { time: moment(timestampDate(session.expirationDate)).fromNow() })}
                <Tooltip.Arrow className="fill-white dark:fill-white/20" />
              </Tooltip.Content>
            </Tooltip.Portal>
          )}
        </Tooltip.Root>
        <button
          type="button"
          onClick={() => removeSession()}
          disabled={busy}
          aria-busy={loading === "remove"}
          aria-label={`${t("removeAccount")}: ${visibleLoginName(session.factors?.user?.loginName) ?? session.factors?.user?.displayName ?? ""}`}
          aria-describedby={hasError ? errorId : undefined}
          className="paypm-session-remove flex flex-shrink-0 items-center justify-center px-3"
        >
          {loading === "remove" ? <Spinner className="h-5 w-5" /> : <XCircleIcon aria-hidden="true" className="h-5 w-5" />}
        </button>
      </div>
      {hasError && (
        <div id={errorId} className="mt-2">
          <Alert>{t("sessionError")}</Alert>
        </div>
      )}
    </div>
  );
}
