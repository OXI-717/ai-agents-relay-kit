declare module "cloudflare:test" {
  interface ProvidedEnv {
    SUBS: KVNamespace;
    DB: D1Database;
    TEST_MIGRATIONS: unknown;
    [key: string]: unknown;
  }
}
export {};
