# ai-agents-relay-kit

Личная VPN-инфраструктура как код, собранная для исполнения **AI-агентом**.

Человек говорит агенту: «Возьми этот кит и всё сделай» — агент по `AGENTS.md`
и `runbooks/` поднимает полный контур: реестр серверов → bootstrap и деплой
xray-серверов (VLESS+XHTTP+Reality) → релейные цепочки с авто-failover →
подписки для клиентов (INCY/Happ, полные xray-конфиги) → подписочный воркер
(Cloudflare) → macOS killswitch с самолечением туннеля.

## Что внутри

| Компонент | Путь | Что делает |
|---|---|---|
| CLI `vpn` | `cmd/vpn/` | validate, uuids, server bootstrap, deploy servers/subs, dist, user bundle, verify |
| Генераторы | `internal/build/` | конфиги серверов, подписки INCY/Happ (полные xray JSON), **failover-цепочки** |
| Реестр | `registry/` (свой) | серверы, пользователи, routing-профили, секреты (SOPS/age) |
| Воркер | `worker/` | раздача подписок с Cloudflare Workers (+routing-заголовок) |
| Killswitch | `deploy/macos/oxi-vpnks` | pf: без VPN — default-deny (LAN+входы), с VPN — снят; самолечение: TUNNEL DEAD-детектор, авто-рестарт клиента, break-glass |
| Verify | `internal/verify/` | сквозные проверки пар релей→выход, geo-preflight, load-тесты |

Ключевая фича — **failover-цепочки** (`docs/failover.md`): при смерти входа
клиент автоматически падает на следующий путь (`YC → CR → direct` стиль) без
участия человека. Реализовано воркараундом XTLS#3114 (fallbackTag + loopback +
burstObservatory) с обязательным DNS→direct правилом — без него в TUN-режиме
системный DNS умирает вместе с первым хопом.

## Быстрый старт (сказать агенту)

> «Склонируй ai-agents-relay-kit, прочитай AGENTS.md и runbooks/, и подними
> мне контур: 2 exit-сервера, 1 релей, подписки на INCY и Happ, killswitch
> на моём Mac. Реестр заполни моими данными, которые я дам».

Агент исполняет фазы из `runbooks/` по порядку, после каждой — гейт проверки.
Dry-run всего контура возможен без единого сервера: `examples/registry/`
(TEST-NET) + `vpn validate` + офлайн-харнес.

## Требования

- macOS или Linux, Go 1.26+, docker (на серверах), Cloudflare аккаунт ( воркер/KV/домен)
- Клиент: INCY Desktop / Happ (полные xray-конфиги), либо любой xray-core
- SOPS + age для секретов реестра

## Документация

- `AGENTS.md` — операционный мануал агента (начинать здесь)
- `runbooks/` — фазы настройки с гейтами проверки
- `docs/failover.md` — архитектура failover-цепочек и инциденты
- `docs/client-notes.md` — интеграция с INCY Desktop: слои DNS, TUN-ловушки, рецепты

## Статус

Рабочий код боевой инфраструктуры, вычищенный от приватных данных. API может
меняться между минорными версиями. Лицензия MIT.
