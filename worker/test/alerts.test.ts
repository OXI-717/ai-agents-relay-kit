import { applyD1Migrations, createExecutionContext, env, fetchMock, SELF, waitOnExecutionContext } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { runAlerts } from "../src/alerts";
import worker from "../src/index";
import type { Env } from "../src/ingest";

const TOKEN = "c".repeat(40);

async function sha256hex(s: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

let tgCalls: { chat_id: string; text: string }[] = [];

beforeAll(async () => {
  await applyD1Migrations(env.DB, env.TEST_MIGRATIONS as never);
  fetchMock.activate();
  fetchMock.disableNetConnect();
  fetchMock.get("https://api.telegram.org")
    .intercept({ path: "/bottok/sendMessage", method: "POST" })
    .reply(200, (r) => {
      tgCalls.push(JSON.parse(String(r.body)));
      return JSON.stringify({ ok: true });
    })
    .persist();
  const h = await sha256hex(TOKEN);
  await env.SUBS.put(`sub:${h}:incy`, "BODY", {
    metadata: { format: "incy", title: "t", content_type: "text/plain", update_interval: "12", user_ref: "ref1234abcd" },
  });
});

describe("alerts", () => {
  it("silent server alerts once, then recovery message", async () => {
    await env.SUBS.put("catalog", JSON.stringify({ servers: [{ id: "kz", enabled: true }], users: [] }));
    await runAlerts(env);
    expect(tgCalls).toHaveLength(1);
    expect(tgCalls[0].text).toContain("kz");
    expect(tgCalls[0]).toMatchObject({ chat_id: "chat", message_thread_id: 42 });
    // still silent → debounced, no resend
    await runAlerts(env);
    expect(tgCalls).toHaveLength(1);
    // heartbeat arrives → recovery
    await env.DB.prepare("INSERT INTO server_state (server, seen_at, payload) VALUES ('kz', ?, '{}')")
      .bind(Math.floor(Date.now() / 1000)).run();
    await runAlerts(env);
    expect(tgCalls).toHaveLength(2);
    expect(tgCalls[1].text).toContain("снова");
  });
});

describe("sub_state", () => {
  it("records last fetch without leaking IP/UA", async () => {
    const r = await SELF.fetch(`https://sub.test/s/${TOKEN}?f=incy`, { headers: { "user-agent": "INCY/9/ios" } });
    expect(r.status).toBe(200);
    await new Promise((r) => setTimeout(r, 50));
    const row = await env.DB.prepare("SELECT * FROM sub_state WHERE user_ref='ref1234abcd'").first<{
      last_fetch_hour: number; client_family: string; format: string;
    }>();
    expect(row).toBeTruthy();
    expect(row!.client_family).toBe("incy");
    expect(row!.format).toBe("incy");
    expect(row!.last_fetch_hour % 3600).toBe(0);
  });

  it("/s works when D1 binding is absent", async () => {
    const ctx = createExecutionContext();
    const noDB = { SUBS: env.SUBS } as unknown as Env;
    const r = await worker.fetch(new Request(`https://sub.test/s/${TOKEN}?f=incy`), noDB, ctx);
    await waitOnExecutionContext(ctx);
    expect(r.status).toBe(200);
    expect(await r.text()).toBe("BODY");
  });
});
