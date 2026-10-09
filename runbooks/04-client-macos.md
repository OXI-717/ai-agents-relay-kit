# Phase 4 — Клиент macOS: killswitch и самолечение

`deploy/macos/oxi-vpnks` — pf-killswitch: без VPN default-deny (наружу только
LAN, DHCP, входы VPN, DNS, Telegram, каналы управления), с VPN — pf снят.
Плюс самолечение: детектор «route есть, трафика нет», авто-рестарт клиента,
break-glass-маршруты каналов управления, heartbeat и ротация лога.

## Установка

```bash
sudo ./deploy/macos/oxi-vpnks install    # LaunchDaemon com.oxi.vpnks
```

`entries.txt` (адреса входов) заполни из реестра или вручную. DoH-резолверы
и Telegram — в whitelist по умолчанию (таблицы `<vpnks_doh>`, `<vpnks_tg>`).

## Проверка

- `oxi-vpnks status` — verdикт по трафику/DNS, туннель, выход.
- Выключи VPN: всё должно умереть, кроме whitelist-каналов; включи — блок
  снимется за ≤10с.

## Инциденты (см. docs/failover.md)

- «route есть, трафика нет» → TUNNEL DEAD → авто-рестарт клиента.
- Системный DNS умирает при живом туннеле → проверь DNS→direct правило
  в конфиге и DoH-таблицу pf.
