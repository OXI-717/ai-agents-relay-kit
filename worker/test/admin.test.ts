import { applyD1Migrations, env, fetchMock, SELF } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

const ISS = "https://team.cloudflareaccess.com";
const AUD = "test-aud-tag";
const EMAIL = "owner@example.com";

let privKey: CryptoKey;
let pubJwk: JsonWebKey & { kid?: string; use?: string; alg?: string };

const b64url = (b: ArrayBuffer | Uint8Array | string) => {
  const bytes = typeof b === "string" ? new TextEncoder().encode(b) : new Uint8Array(b instanceof Uint8Array ? b.buffer : b);
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

async function jwt(payload: Record<string, unknown>): Promise<string> {
  const h = b64url(JSON.stringify({ alg: "RS256", kid: "k1", typ: "JWT" }));
  const p = b64url(JSON.stringify(payload));
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privKey, new TextEncoder().encode(h + "." + p));
  return `${h}.${p}.${b64url(sig)}`;
}

const goodPayload = () => ({
  iss: ISS, aud: [AUD], email: EMAIL, exp: Math.floor(Date.now() / 1000) + 300, iat: 1, sub: "x",
});

beforeAll(async () => {
  await applyD1Migrations(env.DB, (env as unknown as { TEST_MIGRATIONS: never }).TEST_MIGRATIONS);
  const pair = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true, ["sign", "verify"],
  )) as CryptoKeyPair;
  privKey = pair.privateKey;
  pubJwk = await crypto.subtle.exportKey("jwk", pair.publicKey) as typeof pubJwk;
  pubJwk.kid = "k1";
  pubJwk.alg = "RS256";
  pubJwk.use = "sig";
  fetchMock.activate();
  fetchMock.disableNetConnect();
  fetchMock.get(ISS).intercept({ path: "/cdn-cgi/access/certs", method: "GET" }).reply(200, JSON.stringify({ keys: [pubJwk] })).persist();
});

describe("admin", () => {
  it("403 without JWT", async () => {
    expect((await SELF.fetch("https://sub.test/admin/")).status).toBe(403);
    expect((await SELF.fetch("https://sub.test/admin/users")).status).toBe(403);
  });

  it("403 with wrong aud", async () => {
    const t = await jwt({ ...goodPayload(), aud: ["other-aud"] });
    const r = await SELF.fetch("https://sub.test/admin/", { headers: { "Cf-Access-Jwt-Assertion": t } });
    expect(r.status).toBe(403);
  });

  it("403 with expired JWT", async () => {
    const t = await jwt({ ...goodPayload(), exp: Math.floor(Date.now() / 1000) - 10 });
    const r = await SELF.fetch("https://sub.test/admin/", { headers: { "Cf-Access-Jwt-Assertion": t } });
    expect(r.status).toBe(403);
  });

  it("403 with wrong email / bad signature", async () => {
    const t = await jwt({ ...goodPayload(), email: "mallory@example.com" });
    const r = await SELF.fetch("https://sub.test/admin/", { headers: { "Cf-Access-Jwt-Assertion": t } });
    expect(r.status).toBe(403);
    const bad = (await jwt(goodPayload())).slice(0, -2) + "zz";
    expect((await SELF.fetch("https://sub.test/admin/", { headers: { "Cf-Access-Jwt-Assertion": bad } })).status).toBe(403);
  });

  it("200 with valid JWT, escapes HTML", async () => {
    await env.SUBS.put("catalog", JSON.stringify({
      schema_version: 1,
      servers: [{ id: "kz", label: "KZ", kind: "exit", enabled: true, location: "<x>" }],
      users: [{ ref: "f17cac2d378462ea", name: "<b>Имя</b>", status: "active" }],
    }));
    await env.DB.prepare("INSERT INTO server_state (server, seen_at, payload) VALUES ('kz', 1760000000, '{\"gap\":true}')").run();
    await env.DB.prepare("INSERT INTO traffic_hourly (server, user_ref, hour_utc, up, down) VALUES ('kz','f17cac2d378462ea',?,2048,1024)")
      .bind(Math.floor(Date.now() / 3600_000) * 3600).run();
    const t = await jwt(goodPayload());
    const r = await SELF.fetch("https://sub.test/admin/", { headers: { "Cf-Access-Jwt-Assertion": t } });
    expect(r.status).toBe(200);
    const html = await r.text();
    expect(html).toContain("kz");
    expect(html).toContain("gap");
    const u = await SELF.fetch("https://sub.test/admin/users", { headers: { "Cf-Access-Jwt-Assertion": t } });
    const uh = await u.text();
    expect(uh).toContain("&lt;b&gt;Имя&lt;/b&gt;");
    expect(uh).not.toContain("<b>Имя</b>");
  });
});
