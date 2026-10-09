import { defineWorkersConfig, readD1Migrations } from "@cloudflare/vitest-pool-workers/config";

export default defineWorkersConfig(async () => {
  const migrations = await readD1Migrations("migrations");
  return {
    test: {
      poolOptions: {
        workers: {
          wrangler: { configPath: "./wrangler.jsonc" },
          miniflare: {
            kvNamespaces: ["SUBS"],
            d1Databases: ["DB"],
            bindings: {
              TEST_MIGRATIONS: migrations,
              INGEST_HMAC_KZ: "ab".repeat(32),
              ACCESS_ISS: "https://team.cloudflareaccess.com",
              ACCESS_AUD: "test-aud-tag",
              ADMIN_EMAIL: "owner@example.com",
              TG_BOT_TOKEN: "tok",
              TG_CHAT_ID: "chat",
              TG_THREAD_ID: "42",
            },
          },
        },
      },
    },
  };
});
