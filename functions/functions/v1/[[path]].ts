import { proxySupabase } from "../../../shared/pages-proxy";

/** Same-origin passthrough: /functions/v1/* -> Supabase Edge Functions. */
export const onRequest = (ctx: { request: Request }) =>
  proxySupabase(ctx.request, { routeClass: "functions" });
