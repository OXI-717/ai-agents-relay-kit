// Thin subscription server: token → prebuilt subscription from KV. Knows nothing about the registry.
// Stage 2: /ingest (D1), /admin (Access JWT), sub_state, cron alerts — all
// optional-bindings aware: /s/* never depends on D1.
import { handleIngest, type Env } from "./ingest";
import { handleAdmin } from "./admin";
import { runAlerts, runPrune } from "./alerts";

interface Meta {
  format: string;
  title: string;
  content_type: string;
  update_interval: string;
  user_ref?: string;
}

const PATH = /^\/s\/([0-9a-f]{40})$/;
const FORMATS = new Set(["incy", "happ"]);

const empty = (status: number) => new Response(null, { status, headers: { "cache-control": "no-store" } });

async function sha256hex(s: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function clientFamily(ua: string): string {
  if (ua.startsWith("INCY/")) return "incy";
  if (ua.startsWith("Happ/")) return "happ";
  return "other";
}

// sub_state records only the last fetch, hour-rounded, no IP/UA/country (§7.2).
function recordSubState(env: Env, meta: Meta, ua: string, f: string) {
  if (!env.DB || !meta.user_ref) return;
  const hour = Math.floor(Date.now() / 3600_000) * 3600;
  return env.DB.prepare(
    `INSERT INTO sub_state (user_ref, last_fetch_hour, client_family, format) VALUES (?, ?, ?, ?)
     ON CONFLICT (user_ref) DO UPDATE SET last_fetch_hour = excluded.last_fetch_hour,
       client_family = excluded.client_family, format = excluded.format`,
  ).bind(meta.user_ref, hour, clientFamily(ua), f).run().then(() => undefined, () => undefined);
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === "/ingest") return handleIngest(req, env);
    if (url.pathname === "/admin" || url.pathname.startsWith("/admin/")) return handleAdmin(req, env, url.pathname);
    const m = PATH.exec(url.pathname);
    if (!m) return empty(404);
    if (req.method !== "GET" && req.method !== "HEAD") return empty(405);
    // User-Agent is only a hint when f is absent entirely (§6.1); an explicit
    // empty ?f= is a 400, and the UA must start with the client name + "/".
    let f = url.searchParams.get("f") ?? "";
    if (!url.searchParams.has("f")) {
      const ua = req.headers.get("user-agent") ?? "";
      if (ua.startsWith("Happ/")) f = "happ";
      else if (ua.startsWith("INCY/")) f = "incy";
    }
    if (!FORMATS.has(f)) return empty(400);
    const key = `sub:${await sha256hex(m[1])}:${f}`;
    const { value, metadata } = await env.SUBS.getWithMetadata<Meta>(key);
    if (value === null || !metadata) return empty(404);
    ctx.waitUntil(Promise.resolve(recordSubState(env, metadata, req.headers.get("user-agent") ?? "", f)));
    const headers: Record<string, string> = {
      "content-type": metadata.content_type,
      "profile-title": metadata.title,
      "profile-update-interval": metadata.update_interval,
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    };
    // Happ and INCY subscriptions are JSON arrays of full configs — the routing
    // profile cannot ride in the body, so it ships as a response header.
    if (f === "happ" || f === "incy") {
      const routing = await env.SUBS.get(`${key}:routing`);
      if (routing) headers.routing = routing;
    }
    return new Response(req.method === "HEAD" ? null : value, { headers });
  },
  async scheduled(_ctrl: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(runAlerts(env).then(() => runPrune(env)).catch(() => {}));
  },
} satisfies ExportedHandler<Env>;
