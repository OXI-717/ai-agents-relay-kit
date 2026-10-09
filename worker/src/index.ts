// Thin subscription server: token → prebuilt subscription from KV. Knows nothing about the registry.
interface Env {
  SUBS: KVNamespace;
}

interface Meta {
  format: string;
  title: string;
  content_type: string;
  update_interval: string;
}

const PATH = /^\/s\/([0-9a-f]{40})$/;
const FORMATS = new Set(["incy", "happ"]);

const empty = (status: number) => new Response(null, { status, headers: { "cache-control": "no-store" } });

async function sha256hex(s: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
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
} satisfies ExportedHandler<Env>;
