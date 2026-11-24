#!/bin/bash
# U-45 메일 서비스 버전 점검  (엑셀 X: 점검·목록만)
# 기준: 메일 서비스(sendmail/postfix/exim)가 최신 보안 패치 상태. 최신 여부는 외부 정보가 필요해 버전만 보여 준다.
# 계약: bash U-45.sh check|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
set -u
export LC_ALL=C
state() { printf '%s|%s\n' "$1" "$2"; }
have() { command -v "$1" >/dev/null 2>&1; }
pkg_ver() { if have rpm; then rpm -q "$1" 2>/dev/null | grep -v 'not installed'; elif have dpkg; then dpkg -s "$1" 2>/dev/null | awk -F': ' '/^Status:/{s=$2} /^Version:/{v=$2} END{if (s ~ /installed/) print "'"$1"'-" v}'; fi; }
found=()
for p in sendmail postfix exim exim4; do v=$(pkg_ver "$p"); [ -n "$v" ] && found+=("$v"); done
# 패키지가 없을 때: 관련 설정이 남아 있으면 점검 필요(MANUAL), 아무것도 없으면 해당없음(NA)
leftover() { local p f; for p in "$@"; do for f in $p; do [ -e "$f" ] || continue
  if [ -d "$f" ]; then [ -n "$(ls -A "$f" 2>/dev/null)" ] && echo "$f"
  elif [ -f "$f" ] && grep -Eqv '^[[:space:]]*(#|;|$)' "$f" 2>/dev/null; then echo "$f"; fi; done; done; }
pkg_gate() { local label=$1 pkgs=$2 rc l; shift 2; pkg_any $pkgs; rc=$?; [ "$rc" -eq 1 ] || return 0
  l=$(leftover "$@" | head -5 | tr '\n' ' ')
  if [ -n "${l// /}" ]; then state MANUAL "$label 패키지는 설치되어 있지 않으나 관련 파일이 남아 있습니다(점검 필요): $l"
  else state NA "$label 패키지가 설치되어 있지 않고 관련 파일도 없어 점검 대상이 아닙니다"; fi; exit 0; }
pkg_has() { pkg_any "$@"; [ $? -ne 1 ]; }
pkg_any() { [ "${#found[@]}" -gt 0 ] && return 0; return 1; }
pkg_gate "메일 서비스" "x" "/etc/mail/sendmail.cf" "/etc/postfix/main.cf" "/etc/exim" "/etc/exim4"
case "${1:-}" in
  list) have rpm && for p in sendmail postfix exim; do rpm -q --qf '%{NAME}\t버전=%{VERSION}-%{RELEASE} 설치일=%{INSTALLTIME:date}\n' "$p" 2>/dev/null | grep -v 'not installed'; done
        state GOOD "${#found[@]}개 패키지" ;;
  check) printf '%s\n' "${found[@]}"; state MANUAL "메일 서비스 설치됨(${found[*]}): 최신 보안 패치인지 벤더 공지와 비교 확인 필요 (미사용이면 서비스 중지)" ;;
  *) echo "usage: U-45.sh check|list" >&2; exit 2 ;;
esac
