# Клиентские заметки: INCY Desktop (уроки 8–9.10.2026)

Живой опыт интеграции наших подписок (полные xray-конфиги) с INCY Desktop 3.8.2
на macOS. Дока разработчика:
https://incy.gitbook.io/docs (сам docs.incy.cc бывает недоступен; зеркальный
источник — web.archive.org).

## Слои DNS (главная причина «вчера работало — сегодня нет»)

| Слой | Кто управляет | Где живёт | На враждебной сети |
|---|---|---|---|
| TUN-перехват системного DNS (198.18.0.2 → forwarders) | INCY: `tun.settings.dns` | **plain-IP из dns.servers подписки**; если их нет — из настройки `vpnDns` приложения. DoH-URL игнорирует | работает только если forwarder досягаем по udp/53 |
| dns.servers конфига подписки | наш генератор | DoH-по-IP (`https://1.1.1.1/dns-query`) — работает в SOCKS/PROXY_ONLY режиме | tcp/443 DPI не душит |
| Системный DNS (роутер) | macOS | без перехвата | часто отравлен частично |

Следствия:
- **plain-IP в dns.servers подписки запрещены** (реальный кейс: INCY брал их
  как forwarders перехвата; на сети с зарезанным зарубежным udp/53 DNS умирал
  целиком). Валидатор пропускает только `IP` и `https://<ip>/dns-query`.
- `vpnDns` в настройках INCY (файл `~/Library/Application Support/incy/
  preferences.json`, править только при закрытом приложении): на враждебных
  сетях — `1.1.1.1,8.8.8.8,77.88.8.8,77.88.8.1` (Яндекс — последний рубеж,
  только там, где зарубежный udp/53 зарезан). На обычных сетях достаточно
  первых двух.
- Статус в оxi-vpnks (`dns:` в вердикте) различает «туннель жив, DNS мёртв».

## TUN-режим: внутренности и ловушки

- Имя интерфейса **захардкожено в байткоде**: `isMac() ? "utun244"` (service/y).
  После смерти процесса юнит освобождается ядром асинхронно; быстрый рестарт →
  `proxy/tun: connection was refused`. Лечение — ждать освобождения по событию
  (guard: `wait_iface_gone`, лимит), при зависании убивать incy-helper.
- **Зомби-ядро xray переживает приложение** и держит socks 127.0.0.1:10808 →
  следующий старт падает `bind: address already in use`. Лечение: добивать
  `pkill -f "resources/bin/xray"`, ждать освобождения порта.
- Bypass-маршруты при TUN INCY выводит только для **одного** адреса сервера
  (`lastServerIp`) + PUBLIC_DNS_BYPASS → multi-hop full-конфиги (AUTO-цепочки)
  в TUN не работают в принципе. В SOCKS/PROXY_ONLY — работают.
- **SYSTEM_PROXY переключается через osascript с админ-правами** (MacSystemProxy):
  безлюдное переключение виснет на диалоге пароля 120с («user did not dismiss
  password dialog»). Для автоматизации использовать только PROXY_ONLY.
- Режимы: PROXY_ONLY / SYSTEM_PROXY / TUN (enum в `domain/model/e`).

## Залипающее состояние INCY

После серий неудачных подключений INCY не самоочищается: рестарт (quit+open)
НЕ лечит, а **полная смена tunnelMode через закрытое приложение** — лечит
(аналог ручного «удалить подписку и добавить заново», 8.10). Симптом «вчера
работало на той же сети, после перезагрузки нет» → сначала реинициализация,
потом сеть, потом конфиги.

Рецепт реинициализации (guard `heal_incy` v2): quit INCY (graceful → pkill →
pkill зомби-xray) → ждать освобождения utun-юнита и socks-порта → сменить
tunnelMode на PROXY_ONLY → launch → дождаться socks_alive → settle 10с →
quit → вернуть исходный режим → launch → ждать туннель (лимит 45с).
Rate-limit 2/час. Работает и при блоке OFF (`HEAL_OFF_MODE=1`; pf не трогается,
отсутствие VPN при OFF = выбор владельца, не лечим).

## Наш pf-блок: что обязан пропускать

- **DoH-резолверы 1.1.1.1/8.8.8.8 tcp+udp 443** (таблица `<vpnks_doh>`) — иначе
  наш же блок режал DoH в окне подключения: «при снятом блоке INCY запускается,
  при стоящем — нет» (9.10).
- udp/tcp 53 любому — иначе mDNSResponder виснет (Air, 5.10), в т.ч. намертво
  внутри do_apply.
- Демон не должен иметь путей зависнуть: все резолвы через `to <N>` (kill-9 по
  таймауту), весь do_apply — бюджет 25с (`APPLY_DEADLINE`), иначе блок остаётся
  навсегда при вернувшемся туннеле (9.10 12:36).
- **Единственный pf-менеджер — oxi-vpnks**; killswitch INCY выключен в его UI
  (решение владельца 9.10: два pf-менеджера дерутся за правила).

## Диагностика

- `~/bin/oxi-vpnks status` — вердикт по трафику/DNS, последние события guard.
- Офлайн-проверка цепочки: `bin/xray run -c <конфиг из подписки>` +
  `curl --socks5-hostname 127.0.0.1:10808` (порт фиксирован INCY);
  `XRAY_LOCATION_ASSET=/var/tmp/incy-xray/geo`. `xray run -test` — только
  синтаксис.
- Рантайм-конфиг INCY: `/var/tmp/incy-xray/config.json` (какой forwarder взял
  перехват — смотреть там), лог: `/var/tmp/incy-xray/xray.log`.
- Настройки INCY: `~/Library/Application Support/incy/preferences.json`
  (tunnelMode, vpnDns, killSwitch, autoConnect).
- Живой замер сети: мониторы-снимки (маршруты/DNS/хопы) в /var/tmp — рецепты
  в истории коммитов oxi-vpnks.

## Баг-репорты INCY (не отправлены, доказательная база собрана)

1. Захардкоженный `utun244` для macOS → гонки занятого юнита.
2. `tun.settings.dns` принимает только plain-IP (DoH-URL из vpnDns молча
   отбрасывается) + forwarders берутся из dns.servers подписки в обход vpnDns.
3. Bypass-маршрут только для одного адреса сервера → multi-hop full-конфиги
   мертвы в TUN.
4. Не восстанавливает default route при аварийном выходе.
5. SYSTEM_PROXY через админ-osascript — не автоматизируется.

## Хронология коммитов 9.10

e3d5d8d status-вердикт · f1ece61 DNS→direct во все конфиги · 82fc5b2 DoH+plain
→ потом plain убраны · fb6a37f routing-профиль DoH-по-IP · fcd1932 heal v2 +
HEAL_OFF_MODE · 7b11d38 таймауты резолвов/бюджет apply · a700208 `<vpnks_doh>`
· 82b3013 wait_iface_gone · 1eac606 PROXY_ONLY вместо SYSTEM_PROXY ·
275e4e7 cleanup зависшего helper · f93da97 зомби-xray + wait_port_free.
