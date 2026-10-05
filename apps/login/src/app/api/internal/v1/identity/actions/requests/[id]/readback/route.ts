import { readIdentityAction } from "@/lib/identity-action-service";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function POST(request: Request, context: { params: Promise<{ id: string }> }) {
  return readIdentityAction(request, (await context.params).id);
}
