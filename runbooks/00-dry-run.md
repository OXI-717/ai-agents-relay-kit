# Phase 0 — Dry-run всего контура без серверов

Цель: агент проверяет, что умеет генерировать и валидировать весь контур,
не касаясь боевых машин. Гейт фазы — весь flow зелёный на TEST-NET.

## Шаги

```bash
# 1. Сборка CLI
go build -o bin/vpn ./cmd/vpn

# 2. Валидация example-реестра
./bin/vpn -registry examples/registry validate

# 3. Генерация подписок в temp (не в KV!)
#    (используй dist-команду с флагом -registry examples/registry)

# 4. Офлайн-харнес: каждый сгенерированный полный конфиг
XRAY_LOCATION_ASSET=<geo-каталог> xray run -c <config>
curl --socks5-hostname 127.0.0.1:<socks-port> https://www.google.com/generate_204
```

## Гейты фазы

- `vpn validate` — 0 ошибок
- Все сгенерированные конфиги проходят `xray run -c` (не только `-test`)
- Курл через SOCKS получает ответ

## Что куда дальше

Фаза живая, серверы не нужны. Для боевого прогона переходи к `01-registry.md`.
