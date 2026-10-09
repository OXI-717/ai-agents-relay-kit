# Phase 3 — Подписки и воркер

## Раздача

1. Cloudflare: KV namespace `SUBS`, воркер `worker/` (wrangler deploy),
   домен подписки → custom domain воркера.
2. `vpn -registry <dir> deploy subs` — тела подписок + routing-заголовки в KV.

## Проверка

```bash
curl -sD - "https://sub.<домен>/s/<token>?f=incy"   # JSON, заголовок routing
curl -sD - "https://sub.<домен>/s/<token>?f=happ"   # JSON-массив
```

## Импорт клиентом

- INCY/Happ: добавить подписку по URL → серверы + AUTO-цепочки появятся
  в списке → выбрать `AUTO <EXIT>`.
- Формат: JSON-массив полных xray-конфигов; routing — заголовком `routing`.

## Гейт

Клиент подключается; курл-матрица (RU direct / proxy / DNS) зелёная.
