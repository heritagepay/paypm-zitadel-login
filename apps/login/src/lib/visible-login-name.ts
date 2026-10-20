/** Provisioned workforce usernames are technical identifiers; people recognise their name, not that handle. */
const INTERNAL_LOGIN_NAME = /^paypm-workforce-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function visibleLoginName(loginName?: string): string | undefined {
  if (!loginName) return undefined;
  return INTERNAL_LOGIN_NAME.test(loginName.trim()) ? undefined : loginName;
}
