import { env, SELF } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

const TOKEN = "a".repeat(40);

async function sha256hex(s: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

beforeAll(async () => {
  const h = await sha256hex(TOKEN);
  await env.SUBS.put(`sub:${h}:happ`, "[]", {
    metadata: { format: "happ", title: "base64:VlBO", content_type: "application/json", update_interval: "12" },
  });
  await env.SUBS.put(`sub:${h}:happ:routing`, "happ://routing/onadd/eyJOYW1lIjoiVlBOIn0=");
  await env.SUBS.put(`sub:${h}:incy`, "BASE64BODY", {
    metadata: { format: "incy", title: "base64:VU5JVEUgVlBO", content_type: "application/json", update_interval: "12" },
  });
  await env.SUBS.put(`sub:${h}:incy:routing`, "incy://routing/onadd/eyJOYW1lIjoiVlBOIn0=");
});

describe("subscriptions", () => {
  it("serves known token", async () => {
    const r = await SELF.fetch(`https://sub.test/s/${TOKEN}?f=incy`);
    expect(r.status).toBe(200);
    expect(await r.text()).toBe("BASE64BODY");
    expect(r.headers.get("profile-update-interval")).toBe("12");
    expect(r.headers.get("profile-title")).toBe("base64:VU5JVEUgVlBO");
    expect(r.headers.get("cache-control")).toBe("no-store");
  });

  it("404 unknown token, empty body", async () => {
    const r = await SELF.fetch(`https://sub.test/s/${"b".repeat(40)}?f=incy`);
    expect(r.status).toBe(404);
    expect(await r.text()).toBe("");
  });

  it("happ gets routing profile header", async () => {
    const r = await SELF.fetch(`https://sub.test/s/${TOKEN}?f=happ`);
    expect(r.status).toBe(200);
    expect(r.headers.get("routing")).toBe("happ://routing/onadd/eyJOYW1lIjoiVlBOIn0=");
  });

  it("incy gets routing profile header", async () => {
    const r = await SELF.fetch(`https://sub.test/s/${TOKEN}?f=incy`);
    expect(r.status).toBe(200);
    expect(r.headers.get("routing")).toBe("incy://routing/onadd/eyJOYW1lIjoiVlBOIn0=");
  });

  it("404 known token without that format", async () => {
    const h = await sha256hex(TOKEN);
    await env.SUBS.delete(`sub:${h}:happ`);
    const r = await SELF.fetch(`https://sub.test/s/${TOKEN}?f=happ`);
    expect(r.status).toBe(404);
  });

  it("400 bad or missing format", async () => {
    expect((await SELF.fetch(`https://sub.test/s/${TOKEN}?f=clash`)).status).toBe(400);
    expect((await SELF.fetch(`https://sub.test/s/${TOKEN}`)).status).toBe(400);
  });

  it("format falls back to User-Agent without f", async () => {
    const incy = await SELF.fetch(`https://sub.test/s/${TOKEN}`, { headers: { "user-agent": "INCY/1.2.3/ios" } });
    expect(incy.status).toBe(200);
    expect(await incy.text()).toBe("BASE64BODY");
    const happ = await SELF.fetch(`https://sub.test/s/${TOKEN}`, { headers: { "user-agent": "Happ/1.9.3 (Android)" } });
    expect(happ.status).toBe(200);
    expect(happ.headers.get("routing")).toBe("happ://routing/onadd/eyJOYW1lIjoiVlBOIn0=");
    for (const ua of ["curl/8.0", "incy lowercase", "Mozilla/5.0", "Happiness is garbage", "HAPP/1.0", ""]) {
      const r = await SELF.fetch(`https://sub.test/s/${TOKEN}`, { headers: { "user-agent": ua } });
      expect(r.status, ua).toBe(400);
    }
  });

  it("explicit empty f is 400, no User-Agent fallback", async () => {
    const r = await SELF.fetch(`https://sub.test/s/${TOKEN}?f=`, { headers: { "user-agent": "INCY/1.2.3" } });
    expect(r.status).toBe(400);
  });

  it("explicit f wins over User-Agent", async () => {
    const r = await SELF.fetch(`https://sub.test/s/${TOKEN}?f=incy`, { headers: { "user-agent": "Happ/1.9.3" } });
    expect(r.status).toBe(200);
    expect(await r.text()).toBe("BASE64BODY");
  });

  it("404 on malformed paths", async () => {
    for (const p of ["/", "/s/", "/s/xyz?f=incy", `/s/${TOKEN.toUpperCase()}?f=incy`, `/s/${TOKEN}/extra?f=incy`, "/admin", "/ingest"]) {
      const r = await SELF.fetch(`https://sub.test${p}`);
      expect(r.status, p).toBe(404);
      expect(await r.text(), p).toBe("");
    }
  });

  it("405 on non-GET", async () => {
    const r = await SELF.fetch(`https://sub.test/s/${TOKEN}?f=incy`, { method: "POST" });
    expect(r.status).toBe(405);
  });
});
