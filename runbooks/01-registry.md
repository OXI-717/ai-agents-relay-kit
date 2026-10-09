# Phase 1 — Приватный реестр

Реестр = данные пользователя. Хранится ОТДЕЛЬНО от этого репо (приватный
каталог или приватный репо), CLI читает через `-registry <dir>` / `VPN_REGISTRY_DIR`.

## Шаги

1. `mkdir -p ~/vpn-data/registry && cd $_`
2. Скопируй структуру из `examples/registry/` (servers/users/routing/cloudflare/pins)
   и замени TEST-NET значения на реальные (хосты, порты, Reality server_names
   под твои домены-прикрытия).
3. Секреты: `sops` + age. Шаблон — `examples/registry/secrets.example.yaml`.
   Ключи UUID генерирует `vpn uuids fill` (после заполнения серверов/пар).
4. Проверка: `vpn -registry ~/vpn-data/registry validate` → 0 ошибок.

## Правила

- Реальные IP/домены/UUID — только здесь. В репо кита их быть не должно
  (CI-сканер это ловит).
- `transport.dns` — только DoH-по-IP (`https://1.1.1.1/dns-query`) или IP.
  Plain-IP в TUN-режиме INCY превращаются в forwarders перехвата и умирают
  на враждебных сетях.
- Exits у релеев: `exits: [am, kz]` — списки выходов, для которых релей
  строит пары. Порядок relays в servers.yaml = приоритет failover-цепочек.

## Гейт

`vpn validate` зелёный; `vpn dist` (dry) создаёт конфиги без ошибок.
