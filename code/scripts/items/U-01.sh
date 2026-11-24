#!/bin/bash
# U-01 root 계정 원격 접속 제한
# 기준: SSH 의 PermitRootLogin 이 no (유효 설정 기준, sshd_config 와 sshd_config.d 모두 확인)
# 계약: bash U-01.sh check|apply|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
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

CF=/etc/ssh/sshd_config
DROP=/etc/ssh/sshd_config.d

have sshd || [ -f "$CF" ] || { state NA "SSH 서버(sshd)가 설치되어 있지 않아 점검 대상이 아닙니다"; exit 0; }

cfiles=()
[ -f "$CF" ] && [ ! -L "$CF" ] && cfiles+=("$CF")
for f in "$DROP"/*.conf; do [ -f "$f" ] && [ ! -L "$f" ] && cfiles+=("$f"); done

# root 접속을 막아도 들어올 수 있는 관리자 계정이 있는지: wheel/sudo 그룹 + 로그인 쉘 + (암호 해시 또는 authorized_keys)
has_admin() {
  local g u h sh hash
  for g in wheel sudo; do
    for u in $(getent group "$g" 2>/dev/null | cut -d: -f4 | tr ',' ' '); do
      [ "$u" = root ] && continue
      sh=$(getent passwd "$u" | cut -d: -f7); h=$(getent passwd "$u" | cut -d: -f6)
      case "$sh" in */nologin|*/false|"") continue ;; esac
      hash=$(getent shadow "$u" 2>/dev/null | cut -d: -f2)
      case "$hash" in ''|'!'*|'*'*) [ -s "$h/.ssh/authorized_keys" ] && return 0 ;; *) return 0 ;; esac
    done
  done
  return 1
}

effective() {
  local v=""
  have sshd && v=$(sshd -T 2>/dev/null | awk '$1 == "permitrootlogin" {print $2}')
  if [ -z "$v" ]; then    # sshd -T 를 쓸 수 없으면 설정 파일에서 첫 번째 값을 읽는다(sshd 는 첫 값을 사용)
    v=$(cat "${cfiles[@]}" 2>/dev/null | awk 'BEGIN{IGNORECASE=1} /^[[:space:]]*PermitRootLogin[[:space:]]/ {print $2; exit}')
    [ -z "$v" ] && v=prohibit-password
  fi
  printf '%s' "${v,,}"
}

case "${1:-}" in
  list) for f in "${cfiles[@]}"; do printf '%s\tsshd 설정 파일\n' "$f"; done; state GOOD "${#cfiles[@]}개 파일" ;;
  check)
    eff=$(effective)
    if [ "$eff" = no ]; then state GOOD "PermitRootLogin = no"
    else state VULN "PermitRootLogin = $eff (기준: no)"; fi ;;
  apply)
    eff=$(effective)
    [ "$eff" = no ] && { state GOOD "이미 PermitRootLogin = no"; exit 0; }
    has_admin || { state ERROR "root 대신 쓸 관리자(wheel/sudo 그룹, 로그인 쉘, 암호 또는 SSH 키가 있는 계정)가 없어 변경하지 않습니다(로그인 잠김 방지). 예: useradd -m -G wheel <계정>; passwd <계정> 후 그 계정으로 로그인되는지 확인"; exit 1; }
    have sshd && ! sshd -t 2>/dev/null && { state ERROR "현재 sshd 설정에 문법 오류가 있어 변경하지 않습니다"; exit 1; }
    set_in=0
    for f in "${cfiles[@]}"; do   # 값이 있는 파일은 no 로 바꾼다
      if grep -Eiq '^[[:space:]]*PermitRootLogin[[:space:]]' "$f"; then
        sed -i -E 's~^([[:space:]]*)PermitRootLogin[[:space:]].*~\1PermitRootLogin no~I' "$f"; set_in=1
      fi
    done
    if [ "$set_in" -eq 0 ] && [ -f "$CF" ]; then   # 어디에도 없으면 첫 Match 블록 앞(없으면 끝)에 추가
      tmp=$(mktemp) && awk '/^[[:space:]]*Match[[:space:]]/ && !d {print "PermitRootLogin no"; d=1} {print} END{if(!d) print "PermitRootLogin no"}' "$CF" > "$tmp" && cat "$tmp" > "$CF"; rm -f "$tmp"
    fi
    if have sshd && ! sshd -t 2>/dev/null; then state ERROR "변경 후 sshd 문법 검사 실패(엔진이 원복합니다)"; exit 1; fi
    if have systemctl; then for s in sshd ssh; do systemctl is-active "$s" >/dev/null 2>&1 && systemctl reload "$s" >/dev/null 2>&1; done; fi
    eff=$(effective)
    if [ "$eff" = no ]; then state GOOD "조치 완료: PermitRootLogin = no (기존 SSH 연결은 유지, 새 연결부터 적용)"
    else state ERROR "조치 후에도 PermitRootLogin = $eff"; exit 1; fi ;;
  *) echo "usage: U-01.sh check|apply|list" >&2; exit 2 ;;
esac
