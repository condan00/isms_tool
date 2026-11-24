#!/bin/bash
# U-47 스팸 메일 릴레이 제한  (엑셀 X: 점검·목록만)
# 기준: 메일 서버가 외부 임의 대상으로의 릴레이를 허용하지 않음
# 계약: bash U-47.sh check|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
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
pkg_gate "메일 서비스" "postfix sendmail exim exim4" "/etc/mail/sendmail.cf" "/etc/postfix/main.cf" "/etc/exim" "/etc/exim4"
CF=/etc/postfix/main.cf; SM=/etc/mail/access
case "${1:-}" in
  list) for f in $CF /etc/mail/sendmail.cf $SM /etc/exim/exim.conf; do [ -f "$f" ] && printf '%s\t메일 설정 파일\n' "$f"; done; state GOOD "목록" ;;
  check)
    if pkg_has postfix && have postconf && [ -f "$CF" ]; then
      rr=$(postconf -h smtpd_relay_restrictions smtpd_recipient_restrictions 2>/dev/null | tr '\n' ' '); mn=$(postconf -h mynetworks 2>/dev/null)
      echo "postfix smtpd_*_restrictions: ${rr:0:150}"; echo "postfix mynetworks: ${mn:0:100}"
      if echo "$mn" | grep -Eq '(^|[ ,])0\.0\.0\.0/0([ ,]|$)'; then state VULN "postfix mynetworks 가 0.0.0.0/0 으로 모든 대상을 릴레이 허용"
      elif echo "$rr" | grep -q 'reject_unauth_destination'; then state GOOD "postfix 가 reject_unauth_destination 으로 외부 릴레이를 거부"
      else state VULN "postfix 에 reject_unauth_destination 설정이 없음(릴레이 제한 미흡 가능)"; fi
    else
      inst=(); pkg_has postfix && inst+=(postfix); pkg_has sendmail && inst+=(sendmail); pkg_has exim exim4 && inst+=(exim)
      state MANUAL "설치된 메일 서비스(${inst[*]:-없음})는 설정 파일에서 릴레이 제한 여부를 수동 확인해야 합니다"
    fi ;;
  *) echo "usage: U-47.sh check|list" >&2; exit 2 ;;
esac
