#!/bin/bash
# U-64 주기적인 보안 패치 및 벤더 권고사항 적용  (엑셀 X: 점검·목록만)
# 기준: 패치 적용 정책이 있고 주기적으로 패치를 적용함. 정책 유무는 자동 판단이 불가능해 자동 업데이트 설정과 최근 패치 이력을 보여 준다.
# 계약: bash U-64.sh check|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
set -u
export LC_ALL=C
state() { printf '%s|%s\n' "$1" "$2"; }
have() { command -v "$1" >/dev/null 2>&1; }
auto=""
if have systemctl; then
  for t in dnf-automatic.timer dnf-automatic-install.timer unattended-upgrades.service apt-daily-upgrade.timer yum-cron.service; do
    systemctl is-enabled "$t" 2>/dev/null | grep -q '^enabled' && auto="$t"
  done
fi
last=""
if have rpm; then last=$(rpm -qa --last 2>/dev/null | head -1)
elif have dpkg && [ -f /var/log/dpkg.log ]; then last=$(grep ' upgrade ' /var/log/dpkg.log 2>/dev/null | tail -1); fi
case "${1:-}" in
  list) [ -f /var/log/dnf.log ] && printf '/var/log/dnf.log\t패키지 관리 로그\n'; [ -f /var/log/dpkg.log ] && printf '/var/log/dpkg.log\t패키지 관리 로그\n'; state GOOD "목록" ;;
  check)
    echo "커널: $(uname -r)"; echo "가장 최근 패키지 변경: ${last:-확인 불가}"; echo "자동 업데이트: ${auto:-미설정}"
    if [ -n "$auto" ]; then state MANUAL "자동 업데이트 설정됨(${auto}). 패치 정책/벤더 권고 확인은 수동으로 필요"
    else state VULN "자동 업데이트 설정이 없음: 패치 적용 정책과 주기를 확인하세요 (최근 변경: ${last:0:80})"; fi ;;
  *) echo "usage: U-64.sh check|list" >&2; exit 2 ;;
esac
