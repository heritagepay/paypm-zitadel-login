"use client";

import { timestampDate } from "@zitadel/client";
import { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { useRef, useState } from "react";
import { Alert, AlertType } from "./alert";
import { SessionItem } from "./session-item";
import { Translated } from "./translated";

type Props = {
  sessions: Session[];
  requestId?: string;
};

export function SessionsList({ sessions, requestId }: Props) {
  const [list, setList] = useState<Session[]>(sessions);
  const [pending, setPending] = useState(false);
  const actionInFlight = useRef(false);
  const visibleSessions = list
    .filter((session) => session?.factors?.user?.loginName)
    // sort by change date descending
    .sort((a, b) => {
      const dateA = a.changeDate ? timestampDate(a.changeDate).getTime() : 0;
      const dateB = b.changeDate ? timestampDate(b.changeDate).getTime() : 0;
      return dateB - dateA;
    });

  return (
    <div className="flex flex-col space-y-2">
      {visibleSessions.length > 0 ? (
        visibleSessions.map((session) => {
          return (
            <SessionItem
              session={session}
              requestId={requestId}
              disabled={pending}
              onActionStart={() => {
                if (actionInFlight.current) {
                  return false;
                }
                actionInFlight.current = true;
                setPending(true);
                return true;
              }}
              onActionEnd={() => {
                actionInFlight.current = false;
                setPending(false);
              }}
              reload={() => {
                setList((currentList) => currentList.filter((s) => s.id !== session.id));
              }}
              key={session.id}
            />
          );
        })
      ) : (
        <Alert type={AlertType.INFO}>
          <Translated i18nKey="noResults" namespace="accounts" />
        </Alert>
      )}
    </div>
  );
}
