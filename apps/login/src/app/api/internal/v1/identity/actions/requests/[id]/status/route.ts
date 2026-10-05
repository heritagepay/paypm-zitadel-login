import { observeIdentityAction } from "@/lib/identity-action-service";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function POST(request: Request, context: { params: Promise<{ id: string }> }) {
  return observeIdentityAction(request, (await context.params).id);
}
