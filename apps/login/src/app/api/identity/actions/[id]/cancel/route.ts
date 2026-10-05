import { cancelIdentityPublicAction } from "@/lib/identity-action-service";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function POST(request: Request, context: { params: Promise<{ id: string }> }) {
  return cancelIdentityPublicAction(request, (await context.params).id);
}
