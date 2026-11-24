#!/bin/bash
# U-60 SNMP Community String 복잡성 설정  (엑셀 X: 점검·목록만)
# 기준: community 문자열이 public/private 이 아니고, 영문+숫자 10자 이상 또는 영문+숫자+특수문자 8자 이상
# 계약: bash U-60.sh check|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
# 주의: community 문자열 값 자체는 어디에도 출력하지 않는다(개수와 판정만).
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
# community 값 추출: rocommunity/rwcommunity 는 2번째 필드, com2sec 는 4번째 필드
strings_() { awk '/^[[:space:]]*(rocommunity6?|rwcommunity6?)[[:space:]]/ {print $2} /^[[:space:]]*com2sec6?[[:space:]]/ {print $4}' "$CF"; }
weak() {
  local s=$1 len=${#1}
  case "$s" in public|private) return 0 ;; esac
  local has_a has_d has_s
  [[ $s =~ [A-Za-z] ]] && has_a=1 || has_a=0; [[ $s =~ [0-9] ]] && has_d=1 || has_d=0; [[ $s =~ [^A-Za-z0-9] ]] && has_s=1 || has_s=0
  if [ $has_a -eq 1 ] && [ $has_d -eq 1 ] && [ $has_s -eq 1 ] && [ "$len" -ge 8 ]; then return 1; fi
  if [ $has_a -eq 1 ] && [ $has_d -eq 1 ] && [ "$len" -ge 10 ]; then return 1; fi
  return 0
}
case "${1:-}" in
  list) printf '%s\tSNMP 설정\n' "$CF"; state GOOD "1개 파일" ;;
  check)
    total=0; bad=0
    while IFS= read -r s; do [ -z "$s" ] && continue; total=$((total+1)); weak "$s" && bad=$((bad+1)); done < <(strings_)
    if [ "$total" -eq 0 ]; then state GOOD "community 문자열 설정 없음(v3 사용 가능성) — v3 비밀번호 복잡도는 수동 확인"
    elif [ "$bad" -gt 0 ]; then state VULN "community 문자열 ${total}개 중 ${bad}개가 기본값이거나 복잡도 기준 미달(값은 출력하지 않음)"
    else state GOOD "community 문자열 ${total}개 모두 복잡도 기준 충족"; fi ;;
  *) echo "usage: U-60.sh check|list" >&2; exit 2 ;;
esac
