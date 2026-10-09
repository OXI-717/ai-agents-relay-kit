#!/usr/bin/env bash
# vpn-helper: the only command vpn-deploy may run as root. Manages vpn-xray releases.
set -euo pipefail
# VPN_HELPER_BASE is for isolated tests; sudo must not preserve caller environment.
BASE=${VPN_HELPER_BASE:-/etc/vpn-xray}
REL=$BASE/releases
CUR=$BASE/current
PREV=$BASE/previous
NAME=vpn-xray
# image runs as uid 65532; root with only NET_BIND_SERVICE can read 0600 config and bind ports below 1024
HARDEN=(--user 0:0 --cap-drop ALL --cap-add NET_BIND_SERVICE --read-only --security-opt no-new-privileges)

die() { echo "vpn-helper: $*" >&2; exit 1; }
valid_ts() { [[ "$1" =~ ^[0-9]{8}T[0-9]{15}Z$ ]] || die "bad release id: $1"; }

run_container() {
  local dir=$1 image
  image=$(cat "$dir/image.txt")
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker run -d --name "$NAME" --network host --restart unless-stopped "${HARDEN[@]}" \
    --label "vpn.release=${dir##*/}" --ulimit nofile=65536:65536 -v "$dir:/etc/xray:ro" "$image" run -c /etc/xray/config.json >/dev/null
}

export LC_ALL=C
umask 077
case "${1:-}" in
  install|activate|rollback|stop|seal|prune) mkdir -p "$BASE" ;;
esac

# install reads stdin BEFORE taking the state lock: a sender that never closes
# stdin must not hold the lock and block a fail-closed stop indefinitely.
if [[ ${1:-} == install ]]; then
  [[ $# == 3 ]] || die "install requires id and image"
  valid_ts "$2"
  [[ "$3" =~ ^ghcr\.io/xtls/xray-core@sha256:[0-9a-f]{64}$ ]] || die "bad image"
  mkdir -p "$REL"
  tmp="$REL/.tmp-$2"
  mkdir -m 700 "$tmp" || die "temporary release exists"
  trap 'rm -rf "$tmp"' EXIT
  install -m 600 /dev/null "$tmp/config.json"
  head -c 1048577 > "$tmp/config.json"
  size=$(wc -c < "$tmp/config.json")
  (( size > 0 && size <= 1048576 )) || die "config must be 1..1048576 bytes"
  install -m 600 /dev/null "$tmp/image.txt"
  printf '%s\n' "$3" > "$tmp/image.txt"
fi

# Serialize state changes, including the barrier check, across helper processes.
# stop gets a much shorter wait: it must not queue for 120 s behind a long deploy;
# on timeout it fails fast and the caller records an unconfirmed stop/revocation.
case "${1:-}" in
  install|activate|rollback|seal|prune)
    exec 9>"$BASE/.lock"
    flock -w 120 9 || die "lock timeout"
    ;;
  stop)
    exec 9>"$BASE/.lock"
    flock -w "${VPN_HELPER_STOP_WAIT:-30}" 9 || die "lock timeout"
    ;;
esac

check_barrier() {
  local target=$1 barrier
  valid_ts "$target"
  if [[ -f $BASE/barrier ]]; then
    barrier=$(cat "$BASE/barrier")
    valid_ts "$barrier"
    [[ ! "$target" < "$barrier" ]] || die "release predates revocation barrier"
  fi
}

case "${1:-}" in
  install)   # payload staged above; only the publish step needs the lock
    [[ ! -e "$REL/$2" && ! -L "$REL/$2" ]] || die "release exists"
    mv "$tmp" "$REL/$2"
    trap - EXIT
    ;;
  test)
    valid_ts "$2"; image=$(cat "$REL/$2/image.txt")
    docker run --rm "${HARDEN[@]}" -v "$REL/$2:/etc/xray:ro" "$image" run -test -c /etc/xray/config.json
    ;;
  activate)
    check_barrier "$2"
    if [[ -L $CUR ]]; then ln -sfn "$(readlink "$CUR")" "$PREV"; fi
    ln -sfn "$REL/$2" "$CUR"
    run_container "$REL/$2"
    ;;
  seal)
    [[ $# == 2 ]] || die "seal requires id"
    id=$2
    check_barrier "$id"
    [[ -L $CUR && $(readlink "$CUR") == "$REL/$id" ]] || die "current release changed"
    container=$(docker inspect -f '{{.State.Running}}|{{index .Config.Labels "vpn.release"}}|{{range .Mounts}}{{if eq .Destination "/etc/xray"}}{{.Source}}{{end}}{{end}}' "$NAME") || die "container unavailable"
    [[ $container == "true|$id|$REL/$id" ]] || die "container release mismatch"
    printf '%s\n' "$id" > "$BASE/barrier.tmp"
    mv "$BASE/barrier.tmp" "$BASE/barrier"
    rm -f "$PREV"
    ;;
  stop)
    docker rm -f "$NAME" >/dev/null
    rm -f "$CUR" "$PREV"
    ;;
  rollback)
    if [[ ! -L $PREV ]]; then
      docker rm -f "$NAME" >/dev/null
      rm -f "$CUR"
      echo "rolled back to empty"
      exit 0
    fi
    check_barrier "$(basename "$(readlink "$PREV")")"
    ln -sfn "$(readlink "$PREV")" "$CUR"
    run_container "$(readlink "$CUR")"
    ;;
  status)
    echo "current=$(basename "$(readlink "$CUR" 2>/dev/null || echo none)")"
    echo "previous=$(basename "$(readlink "$PREV" 2>/dev/null || echo none)")"
    echo "container=$(docker inspect -f '{{.State.Status}}' "$NAME" 2>/dev/null || echo absent)"
    ss -ltnpH | awk '/"xray"/ {print "listen=" $4}'
    ;;
  prune)    # keep last 5 releases; staging .tmp-* and anything not shaped like
            # a release id is never pruned (a parallel install may be using it)
    find "$REL" -mindepth 1 -maxdepth 1 -type d \
      -name '[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z' \
      -print | sort | awk '{a[NR]=$0} END {for (i = 1; i <= NR - 5; i++) print a[i]}' |
      while IFS= read -r d; do rm -rf "$d"; done
    ;;
  *) die "usage: install|test|activate <id> | rollback | stop | seal <id> | status | prune" ;;
esac
