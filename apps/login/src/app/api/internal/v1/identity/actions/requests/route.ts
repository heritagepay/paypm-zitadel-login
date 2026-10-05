import { startIdentityAction } from "@/lib/identity-action-service";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  return startIdentityAction(request);
}
