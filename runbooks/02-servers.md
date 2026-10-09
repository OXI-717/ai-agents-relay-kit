# Phase 2 — Серверы

Требования к серверу: Ubuntu 22.04/24.04, docker, root SSH с ключом из
`ssh.key` реестра. Провижининг VPS — вне скоупа кита (панель провайдера).

## Шаги

```bash
vpn -registry <dir> uuids fill          # UUID для всех пар/сервисов
vpn -registry <dir> server bootstrap -server <id>   # первый подъём (sudo-пользователь)
vpn -registry <dir> deploy servers      # релизы xray на все серверы
vpn -registry <dir> verify              # сквозные пробы пар + geo-preflight
```

## Гейты

- `vpn verify` — все пары релей→выход зелёные
- Reality handshake с каждого клиента проверяется на фазе 3

## Инциденты

- SSH «REMOTE HOST IDENTIFICATION CHANGED» после перестановки сервера:
  `ssh-keygen -R <host>` и повторить.
- Нет sudo-идентичности на сервере → bootstrap невозможен, заведи её у провайдера
  (см. docs: bootstrap через sudo-пользователя).
