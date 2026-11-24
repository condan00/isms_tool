#!/bin/bash
# U-27 $HOME/.rhosts, hosts.equiv 사용 금지
# 기준: hosts.equiv/.rhosts 소유자가 root 또는 해당 계정, 권한 600 이하, '+' 설정 없음 (r 계열 서비스 설치 시)
# 계약: bash U-27.sh check|apply|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
# 이 파일은 tools/gen_config_scripts*.py 로 만든다. 고칠 때는 생성기를 고치고 다시 만든다.
set -u
export LC_ALL=C
shopt -s nullglob

state() { printf '%s|%s\n' "$1" "$2"; }
have() { command -v "$1" >/dev/null 2>&1; }

pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}

# 패키지가 없을 때: 관련 설정이 남아 있으면 점검 필요(MANUAL), 아무것도 없으면 해당없음(NA)
leftover() { local p f; for p in "$@"; do for f in $p; do [ -e "$f" ] || continue
  if [ -d "$f" ]; then [ -n "$(ls -A "$f" 2>/dev/null)" ] && echo "$f"
  elif [ -f "$f" ] && grep -Eqv '^[[:space:]]*(#|;|$)' "$f" 2>/dev/null; then echo "$f"; fi; done; done; }
pkg_gate() { local label=$1 pkgs=$2 rc l; shift 2; pkg_any $pkgs; rc=$?; [ "$rc" -eq 1 ] || return 0
  l=$(leftover "$@" | head -5 | tr '\n' ' ')
  if [ -n "${l// /}" ]; then state MANUAL "$label 패키지는 설치되어 있지 않으나 관련 파일이 남아 있습니다(점검 필요): $l"
  else state NA "$label 패키지가 설치되어 있지 않고 관련 파일도 없어 점검 대상이 아닙니다"; fi; exit 0; }
pkg_has() { pkg_any "$@"; [ $? -ne 1 ]; }

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

# 서비스 재적용 도우미: svc_list(스냅샷이 서비스 상태를 복구하도록 알림), svc_act(동작 중인 유닛만 reload/restart)
acted=(); failed_svc=""
svc_list() {
  have systemctl || return 0
  local u
  for u in "$@"; do
    [ -n "$(systemctl list-unit-files "$u" --no-legend 2>/dev/null)" ] || continue
    printf '@service\t%s\tenabled=%s\tactive=%s\n' "$u" "$(systemctl is-enabled "$u" 2>/dev/null | tr -c 'a-z\n-' '-' | head -1)" "$(systemctl is-active "$u" 2>/dev/null | tr -c 'a-z\n-' '-' | head -1)"
  done
  return 0
}
svc_act() {    # svc_act reload|restart 유닛... : 동작 중인 유닛만 처리, 처리 후 동작하지 않으면 1(failed_svc 에 유닛 이름)
  local a=$1 u; shift
  have systemctl || return 0
  for u in "$@"; do
    systemctl is-active "$u" >/dev/null 2>&1 || continue
    systemctl "$a" "$u" >/dev/null 2>&1; sleep 1
    systemctl is-active "$u" >/dev/null 2>&1 || { failed_svc=$u; return 1; }
    acted+=("$a:$u")
  done
  return 0
}

nl_end() { [ -s "$1" ] && [ -n "$(tail -c1 "$1")" ] && echo >> "$1"; return 0; }

# kv_get 파일 키 : 마지막 비주석 설정값(구분자는 공백 또는 =). 없으면 빈 문자열
kv_get() {
  awk -v k="$2" '/^[[:space:]]*#/ {next}
    { if (match($0, "^[[:space:]]*" k "([[:space:]]*=[[:space:]]*|[[:space:]]+)")) { v = substr($0, RLENGTH + 1); sub(/[[:space:]]+$/, "", v); r = v; f = 1 } }
    END { if (f) print r }' "$1" 2>/dev/null
}

# kv_set 파일 키 값 구분자 : 비주석 줄이 있으면 값을 바꾸고, 없으면 끝에 추가
kv_set() {
  local f=$1 k=$2 v=$3 sep=$4
  if grep -Eq "^[[:space:]]*$k([[:space:]]*=|[[:space:]])" "$f"; then
    sed -i -E "s~^[[:space:]]*$k([[:space:]]*=[[:space:]]*|[[:space:]]+).*~$k$sep$v~" "$f"
  else
    nl_end "$f"; printf '%s%s%s\n' "$k" "$sep" "$v" >> "$f"
  fi
}

# login_users : 로그인 가능한 계정(UID 0 또는 1000 이상, nologin/false 제외)을 "계정<TAB>홈<TAB>그룹ID" 로 출력
login_users() {
  local u uid gid home shell
  while IFS=: read -r u _ uid gid _ home shell; do
    { [ "$uid" -eq 0 ] || [ "$uid" -ge 1000 ]; } 2>/dev/null || continue
    case "$shell" in */nologin|*/false|"") continue ;; esac
    printf '%s\t%s\t%s\n' "$u" "$home" "$gid"
  done < <(getent passwd)
}

# r 계열 패키지가 없어도(Rocky 9 에는 rsh 패키지가 없다) 파일 자체가 점검·조치 대상이다: 파일이 없으면 해당없음, 있으면 기준 점검

# 줄마다: 경로<TAB>허용 소유자(공백 구분)
collect() {
  [ -f /etc/hosts.equiv ] && [ ! -L /etc/hosts.equiv ] && printf '/etc/hosts.equiv\troot\n'
  login_users | while IFS=$'\t' read -r u h g; do
    [ -f "$h/.rhosts" ] && [ ! -L "$h/.rhosts" ] && printf '%s/.rhosts\troot %s\n' "$h" "$u"
  done
}
mapfile -t rows < <(collect)
[ "${#rows[@]}" -gt 0 ] || { state NA "hosts.equiv/.rhosts 파일이 없습니다"; exit 0; }
bad=(); bad_allowed=(); info=()
scan() {
  bad=(); bad_allowed=(); info=(); local r f allowed owner mode why
  for r in "${rows[@]}"; do
    f=${r%%$'\t'*}; allowed=" ${r#*$'\t'} "; why=""
    read -r owner mode < <(stat -c '%U %a' "$f")
    case "$allowed" in *" $owner "*) ;; *) why="소유자=$owner " ;; esac
    [ $(( 8#$mode & ~8#600 & 8#7777 )) -ne 0 ] && why="${why}권한=$mode "
    grep -Eq '^[[:space:]]*\+' "$f" && why="${why}'+' 설정 있음 "
    [ -n "$why" ] && { bad+=("$f"); bad_allowed+=("${r#*$'\t'}"); info+=("$f"$'\t'"$why"); }
  done
}
case "${1:-}" in
  list) for r in "${rows[@]}"; do printf '%s\t%s\n' "${r%%$'\t'*}" "r 계열 인증 파일"; done; state GOOD "${#rows[@]}개 파일" ;;
  check) scan
    if [ "${#bad[@]}" -gt 0 ]; then printf '%s\n' "${info[@]}"; state VULN "기준 미달 파일 ${#bad[@]}개"; else state GOOD "${#rows[@]}개 파일 모두 기준 충족"; fi ;;
  apply) scan
    for i in "${!bad[@]}"; do
      f=${bad[$i]}; read -r _ first rest <<<"x ${bad_allowed[$i]}"; own=${rest:-$first}
      owner=$(stat -c '%U' "$f"); case " ${bad_allowed[$i]} " in *" $owner "*) ;; *) safe_fix "$f" "$own" ;; esac
      mode=$(stat -c '%a' "$f"); [ $(( 8#$mode & ~8#600 & 8#7777 )) -ne 0 ] && safe_fix "$f" "" "$(printf '%o' $(( 8#$mode & 8#600 )))"
      sed -i -E 's/^([[:space:]]*\+)/#\1/' "$f"
    done
    scan
    if [ "${#bad[@]}" -gt 0 ]; then state ERROR "조치 후에도 ${#bad[@]}개 파일이 기준 미달"; exit 1; fi
    state GOOD "조치 완료: 소유자·권한(600) 정리, '+' 설정은 주석 처리" ;;
  *) echo "usage: U-27.sh check|apply|list" >&2; exit 2 ;;
esac
