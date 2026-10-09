import { applyD1Migrations, env, SELF } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

const KEY = "ab".repeat(32);
const enc = new TextEncoder();

const hex = (d: ArrayBuffer) => [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
const hexBytes = (h: string) => new Uint8Array(h.match(/../g)!.map((b) => parseInt(b, 16)));

async function sign(key: string, server: string, ts: number, batchID: string, body: Uint8Array): Promise<string> {
  const k = await crypto.subtle.importKey("raw", hexBytes(key) as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const digest = await crypto.subtle.digest("SHA-256", body as BufferSource);
  const canon = `POST\n/ingest\n${server}\n${ts}\n${batchID}\n${hex(digest)}`;
  return hex(await crypto.subtle.sign("HMAC", k, enc.encode(canon)));
}

async function post(opts: { server?: string; ts?: number; batch?: string; key?: string; body?: unknown; sig?: string }) {
  const body = enc.encode(JSON.stringify(opts.body ?? {}));
  const server = opts.server ?? "kz";
  const ts = opts.ts ?? Math.floor(Date.now() / 1000);
  const batch = opts.batch ?? crypto.randomUUID();
  const sig = opts.sig ?? (await sign(opts.key ?? KEY, server, ts, batch, body));
  return SELF.fetch("https://sub.test/ingest", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "X-VPN-Server": server,
      "X-VPN-Timestamp": String(ts),
      "X-VPN-Batch": batch,
      "X-VPN-Signature": sig,
    },
    body,
  });
}

const batchBody = (batch: string) => ({
  schema_version: 1,
  server: "kz",
  batch_id: batch,
  measured_at: 1760000000,
  stats: [{ user_ref: "f17cac2d378462ea", up: 100, down: 50 }],
  service_stats: [{ key: "svc:tw>kz", up: 7, down: 8 }],
  heartbeat: { agent_version: "0.2.0", xray_uptime: 300, online: 2, gap: false },
});

beforeAll(async () => {
  await applyD1Migrations(env.DB, env.TEST_MIGRATIONS as never);
});

describe("ingest", () => {
  it("accepts a valid signed batch and writes counters", async () => {
    const batch = crypto.randomUUID();
    const r = await post({ batch, body: batchBody(batch) });
    expect(r.status).toBe(200);
    expect((await r.json() as { ack: boolean }).ack).toBe(true);
    const row = await env.DB.prepare("SELECT * FROM traffic_hourly WHERE server='kz'").first<{ up: number; down: number; hour_utc: number }>();
    expect(row).toMatchObject({ up: 100, down: 50, hour_utc: Math.floor(1760000000 / 3600) * 3600 });
    const svc = await env.DB.prepare("SELECT * FROM service_traffic_hourly WHERE server='kz'").first<{ up: number }>();
    expect(svc?.up).toBe(7);
    const st = await env.DB.prepare("SELECT payload FROM server_state WHERE server='kz'").first<{ payload: string }>();
    expect(JSON.parse(st!.payload).agent_version).toBe("0.2.0");
  });

  it("rejects a bad signature", async () => {
    const batch = crypto.randomUUID();
    const r = await post({ batch, body: batchBody(batch), key: "cd".repeat(32) });
    expect(r.status).toBe(403);
  });

  it("rejects an expired timestamp", async () => {
    const batch = crypto.randomUUID();
    const ts = Math.floor(Date.now() / 1000) - 600;
    const r = await post({ batch, body: batchBody(batch), ts });
    expect(r.status).toBe(403);
  });

  it("duplicate batch_id acks without double counting", async () => {
    const batch = crypto.randomUUID();
    const body = { ...batchBody(batch), stats: [{ user_ref: "aaaa1111bbbb2222", up: 33, down: 0 }], service_stats: [] };
    const r1 = await post({ batch, body });
    expect(r1.status).toBe(200);
    const r2 = await post({ batch, body });
    expect(r2.status).toBe(200);
    expect((await r2.json() as { duplicate?: boolean }).duplicate).toBe(true);
    const row = await env.DB.prepare(
      "SELECT up FROM traffic_hourly WHERE user_ref='aaaa1111bbbb2222'",
    ).first<{ up: number }>();
    expect(row!.up).toBe(33);
  });

  it("rejects unknown server and malformed headers", async () => {
    expect((await post({ server: "nope" })).status).toBe(403);
    expect((await SELF.fetch("https://sub.test/ingest", { method: "POST", body: "{}" })).status).toBe(403);
    expect((await SELF.fetch("https://sub.test/ingest", { method: "GET" })).status).toBe(405);
  });
});
