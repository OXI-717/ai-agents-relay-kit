#!/usr/bin/env bash
# Санитизация: репозиторий не должен содержать приватных идентификаторов
# реальной инфраструктуры. Хук pre-push / шаг CI.
#
# Для СВОЕГО деплоя владелец кладёт рядом (git-игнорируемый) файл
# .private-blocklist.txt — по одному регулярному выражению на строку
# (реальные IP, домены, UUID-префиксы). В публичном репо его нет.
set -u
fail=0

# 1. SOPS/age payloads и приватные ключи не должны коммититься нигде, кроме
#    разрешённых путей (fixtures с synthetic-данными разрешены).
while IFS= read -r f; do
  echo "FAIL: зашифрованный payload вне разрешённых путей: $f"
  fail=1
done < <(grep -rlE 'ENC\[AES256_GCM|AGE-SECRET-KEY|BEGIN (RSA |OPENSSH )?PRIVATE KEY' \
  --include='*.go' --include='*.yaml' --include='*.json' --include='*.sh' --include='*.ts' . \
  | grep -vE 'testdata/|_test\.go|scripts/scan-private\.sh' || true)

# 2. Реальные (не TEST-NET/documentation) IPv4 в исходниках и примерах.
#    Разрешены: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (RFC 5737),
#    127.0.0.0/8, 8.8.8.8/8.8.4.4/1.1.1.1 (публичные резолверы/пробы),
#    91.108.x/149.154.x (публичные CIDR Telegram), 100.64/10 (CGNAT).
bad=$(grep -rnoE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' \
  --include='*.go' --include='*.sh' --include='*.md' --include='*.yaml' --include='*.json' --include='*.jsonc' . 2>/dev/null \
  | grep -vE '/(node_modules|\.git)/' \
  | grep -vE ':(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|127\.0\.0\.[0-9]|8\.8\.8\.8|8\.8\.4\.4|1\.1\.1\.1|1\.0\.0\.1|77\.88\.8\.[0-9]|198\.18\.[0-9]|91\.108\.|149\.154\.|100\.64\.|100\.65\.|185\.76\.151|95\.161\.|224\.0\.0\.|255\.255\.255\.255|10\.0\.0\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168\.|169\.254\.|0\.0\.0\.0|104\.16\.)' \
  | head -20 || true)
if [ -n "$bad" ]; then
  echo "FAIL: подозрительные внешние IPv4 (добавь в allowlist или убери):"
  echo "$bad"
  fail=1
fi

# 3. Приватный блок-лист владельца (локальный файл, не коммитится).
if [ -f .private-blocklist.txt ]; then
  while IFS= read -r pat; do
    [ -z "$pat" ] && continue
    case "$pat" in \#*) continue ;; esac
    hits=$(grep -rnE "$pat" --include='*.go' --include='*.sh' --include='*.md' --include='*.yaml' --include='*.json' --include='*.ts' --include='*.jsonc' . 2>/dev/null | grep -vE '/(node_modules|\.git)/' | head -5)
    if [ -n "$hits" ]; then
      echo "FAIL: приватный паттерн [$pat] найден:"
      echo "$hits"
      fail=1
    fi
  done < .private-blocklist.txt
fi

if [ "$fail" -ne 0 ]; then
  echo "SANITIZE: FAIL"
  exit 1
fi
echo "SANITIZE: OK"
