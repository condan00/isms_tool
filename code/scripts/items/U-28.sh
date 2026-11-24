#!/bin/bash
# U-28 접속 IP 및 포트 제한  (엑셀 X: 점검·목록만)
# 기준: TCP Wrapper 또는 방화벽(firewalld/iptables/nftables/ufw)으로 접속 허용 IP·포트를 제한하고 있음
# 계약: bash U-28.sh check|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
# 어떤 IP/포트가 '맞는' 정책인지는 환경마다 달라 방화벽/규칙이 있는지까지만 판단하고 내용 확인은 사람이 한다.
set -u
export LC_ALL=C
state() { printf '%s|%s\n' "$1" "$2"; }
have() { command -v "$1" >/dev/null 2>&1; }

found=(); info=()
if [ -f /etc/hosts.deny ] && grep -Eq '^[[:space:]]*ALL[[:space:]]*:[[:space:]]*ALL' /etc/hosts.deny; then found+=("tcp_wrappers"); info+=("/etc/hosts.deny: ALL:ALL"); fi
if have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then found+=("firewalld"); info+=("firewalld 활성: 기본 zone=$(firewall-cmd --get-default-zone 2>/dev/null)"); fi
if have ufw && ufw status 2>/dev/null | grep -qi '^Status: active'; then found+=("ufw"); info+=("ufw 활성"); fi
if have iptables && [ "$(iptables -S 2>/dev/null | grep -vc '^-P')" -gt 0 ]; then found+=("iptables"); info+=("iptables 규칙 있음"); fi
if have nft && [ -n "$(nft list ruleset 2>/dev/null)" ]; then found+=("nftables"); info+=("nftables 규칙 있음"); fi

case "${1:-}" in
  list) printf '%s\t%s\n' /etc/hosts.allow "TCP Wrapper 허용 목록" /etc/hosts.deny "TCP Wrapper 차단 목록" 2>/dev/null | while IFS=$'\t' read -r p d; do [ -e "$p" ] && printf '%s\t%s\n' "$p" "$d"; done
        state GOOD "방화벽/접근제어 ${#found[@]}종" ;;
  check)
    if [ "${#found[@]}" -gt 0 ]; then printf '%s\n' "${info[@]}"; state MANUAL "접근 제어 수단 있음(${found[*]}): 허용 IP·포트 정책이 맞는지 확인 필요"
    else state VULN "TCP Wrapper/방화벽 어디에도 접속 제한이 설정되어 있지 않음"; fi ;;
  *) echo "usage: U-28.sh check|list" >&2; exit 2 ;;
esac
