import { proxySupabase } from "../../_lib/proxy";

/** Same-origin passthrough: /auth/v1/* -> GoTrue. All auth lives here. */
export const onRequest = (ctx: { request: Request }) =>
  proxySupabase(ctx.request, { routeClass: "auth" });
