#!/bin/bash
# U-50 DNS Zone Transfer 설정  (엑셀 X: 점검·목록만)
# 기준: Zone Transfer 를 허가된 대상에게만 허용(allow-transfer 가 있고 any 가 아님)
# 계약: bash U-50.sh check|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
set -u
export LC_ALL=C
state() { printf '%s|%s\n' "$1" "$2"; }
have() { command -v "$1" >/dev/null 2>&1; }
pkg_any() { local p; if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1; elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1; fi; return 2; }
# 패키지가 없을 때: 관련 설정이 남아 있으면 점검 필요(MANUAL), 아무것도 없으면 해당없음(NA)
leftover() { local p f; for p in "$@"; do for f in $p; do [ -e "$f" ] || continue
  if [ -d "$f" ]; then [ -n "$(ls -A "$f" 2>/dev/null)" ] && echo "$f"
  elif [ -f "$f" ] && grep -Eqv '^[[:space:]]*(#|;|$)' "$f" 2>/dev/null; then echo "$f"; fi; done; done; }
pkg_gate() { local label=$1 pkgs=$2 rc l; shift 2; pkg_any $pkgs; rc=$?; [ "$rc" -eq 1 ] || return 0
  l=$(leftover "$@" | head -5 | tr '\n' ' ')
  if [ -n "${l// /}" ]; then state MANUAL "$label 패키지는 설치되어 있지 않으나 관련 파일이 남아 있습니다(점검 필요): $l"
  else state NA "$label 패키지가 설치되어 있지 않고 관련 파일도 없어 점검 대상이 아닙니다"; fi; exit 0; }
pkg_has() { pkg_any "$@"; [ $? -ne 1 ]; }
pkg_gate "BIND(named)" "bind bind9" "/etc/named.conf" "/etc/bind" "/etc/named"
CONFS=(); for f in /etc/named.conf /etc/bind/named.conf /etc/bind/named.conf.options /etc/named/*.conf; do [ -f "$f" ] && CONFS+=("$f"); done
[ "${#CONFS[@]}" -gt 0 ] || { state NA "named 설정 파일이 없습니다"; exit 0; }
case "${1:-}" in
  list) for f in "${CONFS[@]}"; do printf '%s\tBIND 설정\n' "$f"; done; state GOOD "${#CONFS[@]}개 파일" ;;
  check)
    lines=$(grep -hE '^[[:space:]]*allow-transfer' "${CONFS[@]}" 2>/dev/null | grep -v '^[[:space:]]*//' )
    echo "allow-transfer: ${lines:-없음}"
    if [ -z "$lines" ]; then state VULN "allow-transfer 설정이 없어 Zone Transfer 가 모든 대상에 허용될 수 있음"
    elif echo "$lines" | grep -Eq '\bany\b'; then state VULN "allow-transfer 에 any 가 설정되어 있음"
    else state GOOD "allow-transfer 가 허가된 대상으로 제한되어 있음"; fi ;;
  *) echo "usage: U-50.sh check|list" >&2; exit 2 ;;
esac
