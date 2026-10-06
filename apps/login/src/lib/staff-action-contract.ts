import { exactObject, identityUuid } from "./identity-action-object";
export const identityStaffActions = {
  invitation: "identity.staff.invitation.issue",
  approval: "identity.staff.access.approve",
} as const;
export type StaffActionCommand =
  | { purpose: "staff_invitation"; operationKey: string; input: { email: string; givenName: string; familyName: string } }
  | { purpose: "staff_access_approval"; operationKey: string; requestId: string; requestCommitment: string };
export function staffActionCommand(v: unknown): v is StaffActionCommand {
  if (!v || typeof v !== "object" || Array.isArray(v)) return false;
  const c = v as Record<string, any>;
  if (!identityUuid(c.operationKey)) return false;
  if (c.purpose === "staff_access_approval")
    return (
      exactObject(c, ["purpose", "operationKey", "requestId", "requestCommitment"]) &&
      identityUuid(c.requestId) &&
      typeof c.requestCommitment === "string" &&
      /^[a-f0-9]{64}$/.test(c.requestCommitment)
    );
  return (
    c.purpose === "staff_invitation" &&
    exactObject(c, ["purpose", "operationKey", "input"]) &&
    exactObject(c.input, ["email", "givenName", "familyName"]) &&
    typeof c.input.email === "string" &&
    c.input.email === c.input.email.trim().toLowerCase() &&
    c.input.email.length <= 254 &&
    /^[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(c.input.email) &&
    ["givenName", "familyName"].every(
      (k) =>
        typeof c.input[k] === "string" &&
        c.input[k] === c.input[k].trim() &&
        c.input[k].length > 0 &&
        c.input[k].length <= 100,
    )
  );
}
export const staffCommandAction = (command: StaffActionCommand) =>
  command.purpose === "staff_invitation" ? identityStaffActions.invitation : identityStaffActions.approval;
