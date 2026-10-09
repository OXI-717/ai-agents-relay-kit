// /admin/* — read-only HTML behind a verified Cloudflare Access JWT (spec §6.2, §7.3).
import type { Env } from "./ingest";

const esc = (s: unknown) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

const b64url = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

async function jwks(iss: string): Promise<JsonWebKey[]> {
  const url = iss.replace(/\/$/, "") + "/cdn-cgi/access/certs";
  const cached = await caches.default.match(url);
  if (cached) {
    const j = (await cached.json()) as { keys: JsonWebKey[] };
    return j.keys ?? [];
  }
  const r = await fetch(url);
  if (!r.ok) return [];
  const j = (await r.json()) as { keys: JsonWebKey[] };
  const resp = new Response(JSON.stringify(j), { headers: { "cache-control": "public, max-age=300" } });
  await caches.default.put(url, resp);
  return j.keys ?? [];
}

// verifyAccessJWT returns the owner's email or null (→ 403).
export async function verifyAccessJWT(req: Request, env: Env): Promise<string | null> {
  const token = req.headers.get("Cf-Access-Jwt-Assertion");
  if (!token || !env.ACCESS_ISS || !env.ACCESS_AUD || !env.ADMIN_EMAIL) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  let header: { alg?: string; kid?: string }, payload: Record<string, unknown>;
  try {
    header = JSON.parse(new TextDecoder().decode(b64url(parts[0])));
    payload = JSON.parse(new TextDecoder().decode(b64url(parts[1])));
  } catch {
    return null;
  }
  if (header.alg !== "RS256" || !header.kid) return null;
  const keys = await jwks(env.ACCESS_ISS);
  const jwk = keys.find((k) => (k as { kid?: string }).kid === header.kid);
  if (!jwk) return null;
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    b64url(parts[2]) as BufferSource,
    new TextEncoder().encode(parts[0] + "." + parts[1]) as BufferSource,
  );
  if (!ok) return null;
  const now = Math.floor(Date.now() / 1000);
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (payload.iss !== env.ACCESS_ISS || !aud.includes(env.ACCESS_AUD)) return null;
  if (typeof payload.exp !== "number" || payload.exp <= now) return null;
  if (typeof payload.nbf === "number" && payload.nbf > now) return null;
  if (payload.email !== env.ADMIN_EMAIL) return null;
  return payload.email;
}

function page(title: string, body: string): Response {
  return new Response(
    `<!doctype html><meta charset="utf-8"><title>${esc(title)}</title>
<style>body{font:14px/1.4 system-ui;margin:2em}table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:4px 10px;text-align:left}nav a{margin-right:1em}</style>
<nav><a href="/admin/">Серверы</a><a href="/admin/users">Пользователи</a></nav>
<h1>${esc(title)}</h1>${body}`,
    { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" } },
  );
}

const fmtBytes = (n: number) => {
  const u = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
};

const fmtTime = (t: number) => (t ? new Date(t * 1000).toISOString().replace("T", " ").slice(0, 19) + "Z" : "—");

async function catalog(env: Env): Promise<{ servers: { id: string; label: string; enabled: boolean }[]; users: { ref: string; name: string; status: string }[] }> {
  try {
    const raw = await env.SUBS.get("catalog");
    if (raw) {
      const c = JSON.parse(raw);
      return { servers: c.servers ?? [], users: c.users ?? [] };
    }
  } catch { /* admin degrades to empty lists */ }
  return { servers: [], users: [] };
}

export async function handleAdmin(req: Request, env: Env, path: string): Promise<Response> {
  if (req.method !== "GET") return new Response(null, { status: 405 });
  if (!(await verifyAccessJWT(req, env))) return new Response(null, { status: 403 });
  if (!env.DB) return page("admin", "<p>D1 не подключён.</p>");
  const cat = await catalog(env);
  const now = Math.floor(Date.now() / 1000);
  const day = now - 86400, month = now - 30 * 86400;

  if (path === "/admin" || path === "/admin/") {
    const state = await env.DB.prepare("SELECT server, seen_at, payload FROM server_state").all<{
      server: string; seen_at: number; payload: string;
    }>();
    const traffic = await env.DB.prepare(
      `SELECT server,
         SUM(CASE WHEN hour_utc >= ? THEN up + down ELSE 0 END) AS d,
         SUM(CASE WHEN hour_utc >= ? THEN up + down ELSE 0 END) AS m
       FROM traffic_hourly GROUP BY server`,
    ).bind(day - (day % 3600), month - (month % 3600)).all<{ server: string; d: number; m: number }>();
    const tmap = new Map((traffic.results ?? []).map((r) => [r.server, r]));
    const smap = new Map((state.results ?? []).map((r) => [r.server, r]));
    const ids = new Set([...cat.servers.map((s) => s.id), ...smap.keys()]);
    let rows = "";
    for (const id of ids) {
      const st = smap.get(id);
      const t = tmap.get(id);
      let hb: Record<string, unknown> = {};
      try { hb = st ? JSON.parse(st.payload) : {}; } catch { /* keep {} */ }
      const alive = !!st && now - st.seen_at <= 900;
      const catSrv = cat.servers.find((s) => s.id === id);
      rows += `<tr><td>${esc(id)}</td><td>${alive ? "жив" : "молчит"}</td><td>${fmtTime(st?.seen_at ?? 0)}</td>` +
        `<td>${esc(hb.agent_version)}</td><td>${hb.gap ? "gap" : ""}</td>` +
        `<td>${fmtBytes(t?.d ?? 0)}</td><td>${fmtBytes(t?.m ?? 0)}</td><td>${esc(catSrv?.enabled ?? "")}</td></tr>`;
    }
    return page("Серверы",
      `<table><tr><th>Сервер</th><th>Статус</th><th>Heartbeat</th><th>Агент</th><th>Gap</th><th>24 ч</th><th>30 д</th><th>enabled</th></tr>${rows}</table>`);
  }

  if (path === "/admin/users") {
    const traffic = await env.DB.prepare(
      `SELECT user_ref, SUM(up + down) AS d,
         SUM(CASE WHEN hour_utc >= ? THEN up + down ELSE 0 END) AS m,
         MAX(hour_utc) AS last
       FROM traffic_hourly GROUP BY user_ref`,
    ).bind(month - (month % 3600)).all<{ user_ref: string; d: number; m: number; last: number }>();
    const subs = await env.DB.prepare("SELECT * FROM sub_state").all<{
      user_ref: string; last_fetch_hour: number; client_family: string; format: string;
    }>();
    const smap = new Map((subs.results ?? []).map((r) => [r.user_ref, r]));
    const tmap = new Map((traffic.results ?? []).map((r) => [r.user_ref, r]));
    let rows = "";
    for (const u of cat.users) {
      const t = tmap.get(u.ref);
      const s = smap.get(u.ref);
      rows += `<tr><td>${esc(u.name)}</td><td>${esc(u.status)}</td>` +
        `<td>${fmtBytes(t?.d ?? 0)}</td><td>${fmtBytes(t?.m ?? 0)}</td>` +
        `<td>${fmtTime(t?.last ?? 0)}</td><td>${fmtTime((s?.last_fetch_hour ?? 0))}</td>` +
        `<td>${esc(s?.client_family)}</td><td>${esc(s?.format)}</td></tr>`;
    }
    return page("Пользователи",
      `<table><tr><th>Имя</th><th>Статус</th><th>30 д</th><th>за 30 д (итог)</th><th>Последний трафик</th><th>Подписка получена</th><th>Клиент</th><th>Формат</th></tr>${rows}</table>`);
  }
  return new Response(null, { status: 404 });
}
