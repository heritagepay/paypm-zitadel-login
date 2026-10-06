export const identityUuid = (v: unknown): v is string =>
  typeof v === "string" && /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(v);
export const exactObject = (v: unknown, keys: string[]): v is Record<string, any> =>
  !!v && typeof v === "object" && !Array.isArray(v) && Object.keys(v).sort().join(",") === [...keys].sort().join(",");
