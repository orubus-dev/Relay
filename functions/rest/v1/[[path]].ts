import { proxySupabase } from "../../_lib/proxy";

/** Same-origin passthrough: /rest/v1/* -> PostgREST. */
export const onRequest = (ctx: { request: Request }) =>
  proxySupabase(ctx.request, { routeClass: "rest" });
