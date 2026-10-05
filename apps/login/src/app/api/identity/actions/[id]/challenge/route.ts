import { readIdentityPublicChallenge } from "@/lib/identity-action-service";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  return readIdentityPublicChallenge(
    request,
    (await context.params).id,
    request.headers.get("X-PayPM-Ceremony-Capability") ?? "",
  );
}
