#!/bin/bash
# U-59 안전한 SNMP 버전 사용  (엑셀 X: 점검·목록만)
# 기준: SNMP 를 v3 이상으로만 사용(커뮤니티 기반 v1/v2c 설정이 없음)
# 계약: bash U-59.sh check|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
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
    v12=$(grep -Ecv '^[[:space:]]*(#|$)' <(grep -E '^[[:space:]]*(rocommunity6?|rwcommunity6?|com2sec6?)[[:space:]]' "$CF") 2>/dev/null)
    v3=$(grep -Ec '^[[:space:]]*(createUser|rouser|rwuser)[[:space:]]' "$CF")
    if [ "${v12:-0}" -gt 0 ]; then state VULN "v1/v2c 커뮤니티 설정 ${v12}건 존재(v3 이상 사용 권장, v3 사용자 ${v3}건)"
    elif [ "$v3" -gt 0 ]; then state GOOD "v3 사용자 설정만 있음(${v3}건)"
    else state MANUAL "snmpd.conf 에 버전별 접근 설정이 없어 수동 확인 필요"; fi ;;
  *) echo "usage: U-59.sh check|list" >&2; exit 2 ;;
esac
