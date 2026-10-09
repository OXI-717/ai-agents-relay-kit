// POST /ingest — signed traffic batches from vpn-agent (spec §6.2, §7.2).
export interface Env {
  SUBS: KVNamespace;
  DB?: D1Database;
  ACCESS_ISS?: string;
  ACCESS_AUD?: string;
  ADMIN_EMAIL?: string;
  TG_BOT_TOKEN?: string;
  TG_CHAT_ID?: string;
  TG_THREAD_ID?: string;
  [key: string]: unknown;
}

const MAX_BODY = 64 * 1024;
const MAX_ROWS = 500;
const TS_SKEW = 300; // ±5 min

const hex = (d: ArrayBuffer | Uint8Array) =>
  [...new Uint8Array(d instanceof Uint8Array ? d.buffer : d)].map((b) => b.toString(16).padStart(2, "0")).join("");

const hexBytes = (h: string): Uint8Array => {
  const b = new Uint8Array(h.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return b;
};

function timingSafeEq(a: string, b: string): boolean {
  const x = new TextEncoder().encode(a), y = new TextEncoder().encode(b);
  if (x.length !== y.length) return false;
  let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
}

const empty = (status: number) => new Response(null, { status, headers: { "cache-control": "no-store" } });
const json = (o: unknown, status = 200) =>
  new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });

function ingestKeyEnv(server: string): string {
  return "INGEST_HMAC_" + server.toUpperCase().replace(/[-.]/g, "_");
}

interface Batch {
  schema_version: number;
  server: string;
  batch_id: string;
  measured_at: number;
  stats?: { user_ref: string; up: number; down: number }[];
  service_stats?: { key: string; up: number; down: number }[];
  heartbeat?: Record<string, unknown>;
}

export async function handleIngest(req: Request, env: Env): Promise<Response> {
  if (req.method !== "POST") return empty(405);
  const server = req.headers.get("X-VPN-Server") ?? "";
  const ts = Number(req.headers.get("X-VPN-Timestamp"));
  const batchID = req.headers.get("X-VPN-Batch") ?? "";
  const sig = req.headers.get("X-VPN-Signature") ?? "";
  if (!/^[a-z0-9-]{1,32}$/.test(server) || !/^[0-9a-f]{64}$/.test(sig)) return empty(403);
  if (!Number.isInteger(ts) || Math.abs(Date.now() / 1000 - ts) > TS_SKEW) return empty(403);
  const keyHex = env[ingestKeyEnv(server)];
  if (typeof keyHex !== "string" || !/^[0-9a-f]{64}$/.test(keyHex)) return empty(403);
  const body = new Uint8Array(await req.arrayBuffer());
  if (body.byteLength === 0 || body.byteLength > MAX_BODY) return empty(413);
  const digest = await crypto.subtle.digest("SHA-256", body as BufferSource);
  const canon = `POST\n/ingest\n${server}\n${ts}\n${batchID}\n${hex(digest)}`;
  const key = await crypto.subtle.importKey("raw", hexBytes(keyHex) as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const expected = hex(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(canon)));
  if (!timingSafeEq(expected, sig)) return empty(403);

  let b: Batch;
  try {
    b = JSON.parse(new TextDecoder().decode(body));
  } catch {
    return empty(400);
  }
  if (b.schema_version !== 1 || b.server !== server || b.batch_id !== batchID) return empty(400);
  const stats = Array.isArray(b.stats) ? b.stats : [];
  const svc = Array.isArray(b.service_stats) ? b.service_stats : [];
  if (stats.length + svc.length > MAX_ROWS) return empty(413);
  if (!env.DB) return json({ error: "d1 unavailable" }, 503);

  const now = Math.floor(Date.now() / 1000);
  const hour = Math.floor((Number.isInteger(b.measured_at) ? b.measured_at : ts) / 3600) * 3600;
  const stmts: D1PreparedStatement[] = [
    env.DB.prepare("INSERT INTO ingest_batches (server, batch_id, received_at) VALUES (?, ?, ?)").bind(server, batchID, now),
  ];
  const reRef = /^[0-9a-f]{8,64}$/;
  const reSvc = /^svc:[a-z0-9>-]{1,64}$/;
  for (const s of stats) {
    if (!reRef.test(String(s.user_ref))) return empty(400);
    stmts.push(
      env.DB.prepare(
        `INSERT INTO traffic_hourly (server, user_ref, hour_utc, up, down) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (server, user_ref, hour_utc) DO UPDATE SET up = up + excluded.up, down = down + excluded.down`,
      ).bind(server, s.user_ref, hour, Math.max(0, s.up | 0), Math.max(0, s.down | 0)),
    );
  }
  for (const s of svc) {
    if (!reSvc.test(String(s.key))) return empty(400);
    stmts.push(
      env.DB.prepare(
        `INSERT INTO service_traffic_hourly (server, svc, hour_utc, up, down) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (server, svc, hour_utc) DO UPDATE SET up = up + excluded.up, down = down + excluded.down`,
      ).bind(server, s.key, hour, Math.max(0, s.up | 0), Math.max(0, s.down | 0)),
    );
  }
  const hb = JSON.stringify(b.heartbeat ?? {});
  stmts.push(
    env.DB.prepare(
      `INSERT INTO server_state (server, seen_at, payload) VALUES (?, ?, ?)
       ON CONFLICT (server) DO UPDATE SET seen_at = excluded.seen_at, payload = excluded.payload`,
    ).bind(server, now, hb),
    env.DB.prepare("INSERT OR REPLACE INTO server_history (server, seen_at, payload) VALUES (?, ?, ?)").bind(server, now, hb),
  );
  try {
    await env.DB.batch(stmts);
  } catch (e) {
    // PK conflict on ingest_batches rolled the whole batch back → this packet
    // was already committed once; acknowledge without counting twice.
    if (String(e).toLowerCase().includes("constraint")) {
      return json({ ack: true, duplicate: true });
    }
    return json({ error: "d1 write failed" }, 500);
  }
  return json({ ack: true });
}
