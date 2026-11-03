import { proxySupabase } from "../../../shared/pages-proxy";

/** Same-origin passthrough: /storage/v1/* -> Supabase Storage (streamed). */
export const onRequest = (ctx: { request: Request }) =>
  proxySupabase(ctx.request, { routeClass: "storage" });
