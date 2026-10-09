// Cron (*/5): сервер молчит > 15 минут → Telegram; дебаунс 1 ч; восстановление — отдельно.
import type { Env } from "./ingest";

const SILENT_AFTER = 15 * 60;
const DEBOUNCE = 3600;

async function sendTelegram(env: Env, text: string): Promise<void> {
  if (!env.TG_BOT_TOKEN || !env.TG_CHAT_ID) return;
  const body: Record<string, unknown> = { chat_id: env.TG_CHAT_ID, text };
  if (env.TG_THREAD_ID) body.message_thread_id = Number(env.TG_THREAD_ID);
  await fetch(`https://api.telegram.org/bot${env.TG_BOT_TOKEN}/sendMessage`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function runAlerts(env: Env): Promise<void> {
  if (!env.DB) return;
  const now = Math.floor(Date.now() / 1000);
  // Expected servers come from the KV catalog; without it we can only check
  // servers that have reported at least once.
  let expected = new Set<string>();
  try {
    const raw = await env.SUBS.get("catalog");
    if (raw) {
      const c = JSON.parse(raw) as { servers?: { id: string; enabled: boolean }[] };
      for (const s of c.servers ?? []) if (s.enabled) expected.add(s.id);
    }
  } catch { /* fall back to reported servers only */ }
  const rows = await env.DB.prepare("SELECT server, seen_at FROM server_state").all<{ server: string; seen_at: number }>();
  const seen = new Map((rows.results ?? []).map((r) => [r.server, r.seen_at]));
  for (const id of seen.keys()) expected.add(id);

  const alertRows = await env.DB.prepare("SELECT kind, object, sent_at FROM alerts WHERE kind = 'silent'").all<{
    kind: string; object: string; sent_at: number;
  }>();
  const alerted = new Map((alertRows.results ?? []).map((r) => [r.object, r.sent_at]));

  for (const id of expected) {
    const t = seen.get(id);
    const silent = t === undefined || now - t > SILENT_AFTER;
    if (silent) {
      const last = alerted.get(id);
      if (last === undefined) {
        await sendTelegram(env, `🔴 VPN: сервер ${id} молчит более 15 минут (последний heartbeat ${t ? new Date(t * 1000).toISOString() : "никогда"})`);
        await env.DB.prepare("INSERT OR REPLACE INTO alerts (kind, object, sent_at) VALUES ('silent', ?, ?)").bind(id, now).run();
      } else if (now - last >= DEBOUNCE) {
        await sendTelegram(env, `🔴 VPN: сервер ${id} по-прежнему молчит`);
        await env.DB.prepare("UPDATE alerts SET sent_at = ? WHERE kind = 'silent' AND object = ?").bind(now, id).run();
      }
    } else if (alerted.has(id)) {
      await sendTelegram(env, `✅ VPN: сервер ${id} снова на связи`);
      await env.DB.prepare("DELETE FROM alerts WHERE kind = 'silent' AND object = ?").bind(id).run();
    }
  }
}

// Уборка D1 (free tier): единственный источник неограниченного роста —
// ingest_batches (дедуп, хватит 48 ч) и server_history (диагностика, 7 дней).
// traffic_hourly/service_hourly растут медленно (строки на сервер×юзер×час),
// держим 90 дней. Запускается из того же крона; ошибки не роняют алерты.
const KEEP_BATCHES = 48 * 3600;
const KEEP_HISTORY = 7 * 24 * 3600;
const KEEP_HOURLY = 90 * 24 * 3600;

export async function runPrune(env: Env): Promise<void> {
  if (!env.DB) return;
  const now = Math.floor(Date.now() / 1000);
  await env.DB.batch([
    env.DB.prepare("DELETE FROM ingest_batches WHERE received_at < ?").bind(now - KEEP_BATCHES),
    env.DB.prepare("DELETE FROM server_history WHERE seen_at < ?").bind(now - KEEP_HISTORY),
    env.DB.prepare("DELETE FROM traffic_hourly WHERE hour_utc < ?").bind(now - KEEP_HOURLY),
    env.DB.prepare("DELETE FROM service_traffic_hourly WHERE hour_utc < ?").bind(now - KEEP_HOURLY),
  ]);
}
