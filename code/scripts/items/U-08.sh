#!/bin/bash
# U-08 관리자 그룹에 최소한의 계정 포함  (엑셀 ?: 확인 후 적용)
# 기준: 관리자 그룹(root, wheel, sudo, admin)마다 root 외 구성원이 1명 이하
# 조치: root 외 구성원이 2명 이상이면 1명만 남기고 나머지는 그룹에서 제거(gpasswd -d). 남기는 계정은 도구를 sudo 로 실행한 계정(ISMS_INVOKER)이 구성원이면 그 계정,
#       아니면 그룹 목록에서 맨 앞의 계정. 계정 자체는 삭제하지 않는다.
# 계약: bash U-08.sh check|apply|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
# 손으로 쓴 스크립트다(tools/ 생성기 없음).
set -u
export LC_ALL=C
shopt -s nullglob
state() { printf '%s|%s\n' "$1" "$2"; }
have() { command -v "$1" >/dev/null 2>&1; }

GROUPS_=(root wheel sudo admin)
members() { getent group "$1" 2>/dev/null | awk -F: '{print $4}' | tr ',' '\n' | sed '/^$/d' | grep -vx root; }
# plan: "그룹|제거할계정|남길계정"
plan=(); over=0; listing=()
build() { plan=(); listing=(); over=0; local g m keep inv=${ISMS_INVOKER:-}
  for g in "${GROUPS_[@]}"; do
    getent group "$g" >/dev/null 2>&1 || continue
    mapfile -t mem < <(members "$g"); [ "${#mem[@]}" -gt 0 ] && listing+=("$g: ${mem[*]}")
    [ "${#mem[@]}" -gt 1 ] || continue
    over=$((over+1)); keep=${mem[0]}
    for m in "${mem[@]}"; do [ -n "$inv" ] && [ "$m" = "$inv" ] && keep=$inv; done
    for m in "${mem[@]}"; do [ "$m" = "$keep" ] || plan+=("$g|$m|$keep"); done
  done; }
build
case "${1:-}" in
  list) printf '/etc/group\t그룹 구성원(관리자 그룹)\n/etc/gshadow\t그룹 비밀번호/관리자 정보\n'; state GOOD "관리자 그룹 ${#listing[@]}개에 root 외 구성원 있음" ;;
  check)
    if [ "$over" -gt 0 ]; then printf '%s\n' "${listing[@]}"; state VULN "root 외 구성원이 2명 이상인 관리자 그룹 ${over}개 (그룹당 1명까지 허용)"
    else [ "${#listing[@]}" -gt 0 ] && printf '%s\n' "${listing[@]}"; state GOOD "관리자 그룹의 root 외 구성원이 그룹당 1명 이하"; fi ;;
  apply)
    cnt=${#plan[@]}
    for x in "${plan[@]}"; do g=${x%%|*}; r=${x#*|}; r=${r%%|*}; gpasswd -d "$r" "$g" >/dev/null 2>&1 || { state ERROR "$r 를 $g 그룹에서 제거하지 못했습니다"; exit 1; }; done
    build
    if [ "$over" -gt 0 ]; then state ERROR "조치 후에도 구성원이 많은 관리자 그룹이 ${over}개 남았습니다"; exit 1; fi
    state GOOD "조치 완료: ${cnt}개 계정을 관리자 그룹에서 제거(그룹당 1명 유지)" ;;
  *) echo "usage: U-08.sh check|apply|list" >&2; exit 2 ;;
esac
