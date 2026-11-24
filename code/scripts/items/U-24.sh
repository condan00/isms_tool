#!/bin/bash
# U-24 사용자, 시스템 환경변수 파일 소유자 및 권한 설정
# 기준: 환경변수 파일 소유자가 root 또는 해당 계정이고, 소유자·root 외(그룹/기타)에 쓰기 권한이 없음
# 계약: bash U-24.sh check|apply|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
# 대상: 시스템 /etc/profile 등 + 로그인 가능한 계정(UID 0 또는 1000 이상)의 홈 디렉터리 점 파일. 링크는 대상 제외.
set -u
export LC_ALL=C
shopt -s nullglob

state() { printf '%s|%s\n' "$1" "$2"; }
# 열어 둔 파일 기술자(fd)로 소유자/권한을 바꿔, 점검~조치 사이에 심볼릭 링크로 바꿔치기해도 엉뚱한 파일을 건드리지 않는다
safe_fix() { local f=$1 own=${2:-} mod=${3:-} a b rc=0
  [ -L "$f" ] && return 1
  { exec 9<"$f"; } 2>/dev/null || return 1
  a=$(stat -Lc '%d:%i' /proc/self/fd/9 2>/dev/null); b=$(stat -c '%d:%i' "$f" 2>/dev/null)
  if [ -n "$a" ] && [ "$a" = "$b" ]; then
    [ -n "$own" ] && { chown "$own" /proc/self/fd/9 || rc=1; }
    [ -n "$mod" ] && { chmod "$mod" /proc/self/fd/9 || rc=1; }
  else rc=1; fi
  exec 9<&-; return $rc; }
HOME_FILES=(.profile .bash_profile .bash_login .bashrc .bash_logout .zshenv .zprofile .zshrc .zlogin .login .cshrc .tcshrc .kshrc .exrc .env)

# 줄마다: 경로<TAB>허용 소유자(공백 구분)
collect() {
  local f u uid home shell h
  for f in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/environment /etc/csh.cshrc /etc/csh.login /etc/zshrc /etc/profile.d/*; do
    [ -f "$f" ] && [ ! -L "$f" ] && printf '%s\troot\n' "$f"
  done
  while IFS=: read -r u _ uid _ _ home shell; do
    { [ "$uid" -eq 0 ] || [ "$uid" -ge 1000 ]; } 2>/dev/null || continue
    case "$shell" in */nologin|*/false|"") continue ;; esac
    [ -d "$home" ] && [ ! -L "$home" ] || continue
    for h in "${HOME_FILES[@]}"; do
      f="$home/$h"
      [ -f "$f" ] && [ ! -L "$f" ] && printf '%s\troot %s\n' "$f" "$u"
    done
  done < <(getent passwd)
}

mapfile -t rows < <(collect)
bad=(); bad_info=(); badown=()
scan_bad() {
  bad=(); bad_info=(); badown=()
  local row f allowed owner mode
  for row in "${rows[@]}"; do
    f=${row%%$'\t'*}; allowed=" ${row#*$'\t'} "
    read -r owner mode < <(stat -c '%U %a' "$f")
    case "$allowed" in *" $owner "*) o_ok=1 ;; *) o_ok=0 ;; esac
    if [ "$o_ok" -ne 1 ] || [ $(( 8#$mode & 8#022 )) -ne 0 ]; then
      bad+=("$f"); badown+=("${allowed# }"); bad_info+=("$f"$'\t'"소유자=$owner 권한=$mode")
    fi
  done
}

if [ "${#rows[@]}" -eq 0 ]; then state NA "환경변수 파일 대상이 없습니다"; exit 0; fi

case "${1:-}" in
  list)
    for row in "${rows[@]}"; do f=${row%%$'\t'*}; read -r o m < <(stat -c '%U %a' "$f"); printf '%s\t소유자=%s 권한=%s\n' "$f" "$o" "$m"; done
    state GOOD "${#rows[@]}개 파일" ;;
  check)
    scan_bad
    if [ "${#bad[@]}" -gt 0 ]; then printf '%s\n' "${bad_info[@]}"; state VULN "${#bad[@]}개 파일이 기준 미달 (기준: 소유자 root/해당 계정, 그룹·기타 쓰기 금지)"
    else state GOOD "${#rows[@]}개 파일 모두 기준 충족"; fi ;;
  apply)
    scan_bad
    for i in "${!bad[@]}"; do
      f=${bad[$i]}; read -r first rest <<<"${badown[$i]}"
      owner=$(stat -c '%U' "$f"); allowed=" ${badown[$i]} "
      # 소유자가 허용 목록에 없으면: 홈 파일은 해당 계정으로, 시스템 파일은 root 로
      case "$allowed" in *" $owner "*) ;; *) safe_fix "$f" "${rest:-$first}" ;; esac
      mode=$(stat -c '%a' "$f")
      [ $(( 8#$mode & 8#022 )) -ne 0 ] && safe_fix "$f" "" go-w
    done
    scan_bad
    if [ "${#bad[@]}" -gt 0 ]; then state ERROR "조치 후에도 ${#bad[@]}개 파일이 기준 미달"; exit 1; fi
    state GOOD "조치 완료: ${#rows[@]}개 파일 기준 충족" ;;
  *) echo "usage: U-24.sh check|apply|list" >&2; exit 2 ;;
esac
