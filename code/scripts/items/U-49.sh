#!/bin/bash
# U-49 DNS 보안 버전 패치  (엑셀 X: 점검·목록만)
# 기준: DNS(BIND) 서비스를 쓰면 최신 보안 패치 상태. 최신 여부는 외부 정보가 필요해 버전과 설치일만 보여 준다.
# 계약: bash U-49.sh check|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
set -u
export LC_ALL=C
state() { printf '%s|%s\n' "$1" "$2"; }
have() { command -v "$1" >/dev/null 2>&1; }
ver=""
if have rpm && rpm -q bind >/dev/null 2>&1; then ver=$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE} (설치일 %{INSTALLTIME:date})' bind 2>/dev/null)
elif have dpkg && dpkg -s bind9 2>/dev/null | grep -q 'install ok installed'; then ver="bind9-$(dpkg -s bind9 | awk -F': ' '/^Version:/{print $2}')"; fi
if [ -z "$ver" ]; then   # 패키지가 없을 때: 설정이 남아 있으면 점검 필요, 아무것도 없으면 해당없음
  l=""; for f in /etc/named.conf /etc/bind /etc/named; do
    if [ -d "$f" ] && [ -n "$(ls -A "$f" 2>/dev/null)" ]; then l="$l $f"
    elif [ -f "$f" ] && grep -Eqv '^[[:space:]]*(#|;|$)' "$f" 2>/dev/null; then l="$l $f"; fi
  done
  if [ -n "${l// /}" ]; then state MANUAL "BIND 패키지는 설치되어 있지 않으나 관련 파일이 남아 있습니다(점검 필요):$l"
  else state NA "BIND(named) 패키지가 설치되어 있지 않고 관련 파일도 없어 점검 대상이 아닙니다"; fi
  exit 0
fi
case "${1:-}" in
  list) printf '%s\t%s\n' /etc/named.conf "BIND 설정" 2>/dev/null | while IFS=$'\t' read -r p d; do [ -f "$p" ] && printf '%s\t%s\n' "$p" "$d"; done; state GOOD "$ver" ;;
  check) echo "$ver"; state MANUAL "DNS 서비스 설치됨($ver): 최신 보안 패치 여부를 확인하세요 (미사용이면 서비스 중지)" ;;
  *) echo "usage: U-49.sh check|list" >&2; exit 2 ;;
esac
