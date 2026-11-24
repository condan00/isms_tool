#!/bin/bash
# U-61 SNMP Access Control 설정  (엑셀 X: 점검·목록만)
# 기준: SNMP 접근을 특정 호스트/네트워크로 제한(community 에 source 지정, 또는 v3 사용자만 사용)
# 계약: bash U-61.sh check|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
# 주의: community 문자열 값은 출력하지 않는다.
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
pkg_gate "SNMP" "net-snmp snmpd" "/etc/snmp"
CF=""; for f in /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf; do [ -f "$f" ] && CF=$f && break; done
[ -n "$CF" ] || { state NA "snmpd.conf 가 없습니다"; exit 0; }
case "${1:-}" in
  list) printf '%s\tSNMP 설정\n' "$CF"; state GOOD "1개 파일" ;;
  check)
    # rocommunity <문자열> [source]: source 가 없거나 default / 0.0.0.0/0 이면 접근 제어 없음
    open=$(awk '/^[[:space:]]*(rocommunity6?|rwcommunity6?)[[:space:]]/ { if (NF < 3 || $3 == "default" || $3 == "0.0.0.0/0" || $3 == "::/0") n++ } /^[[:space:]]*com2sec6?[[:space:]]/ { if ($3 == "default" || $3 == "0.0.0.0/0") n++ } END{print n+0}' "$CF")
    total=$(grep -Ec '^[[:space:]]*(rocommunity6?|rwcommunity6?|com2sec6?)[[:space:]]' "$CF")
    if [ "$open" -gt 0 ]; then state VULN "접근 대상 제한이 없는 community 설정 ${open}건(전체 ${total}건)"
    elif [ "$total" -gt 0 ]; then state GOOD "community 설정 ${total}건 모두 접근 대상이 제한됨"
    elif grep -Eq '^[[:space:]]*(rouser|rwuser|createUser)[[:space:]]' "$CF"; then state GOOD "v3 사용자 기반 설정(community 없음)"
    else state MANUAL "snmpd.conf 에 접근 제어 설정이 없어 수동 확인 필요"; fi ;;
  *) echo "usage: U-61.sh check|list" >&2; exit 2 ;;
esac
