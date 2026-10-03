import { logoutIdentitySession } from "@/lib/identity-logout";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  return logoutIdentitySession(request);
}
