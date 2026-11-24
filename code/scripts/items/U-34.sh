#!/bin/bash
# U-34 Finger 서비스 비활성화
# 기준: Finger 서비스가 비활성화
# 계약: bash U-34.sh check|apply|list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
# 대상 패키지/유닛/설정이 하나도 없으면 NA. 서비스 상태는 list 의 '@service' 줄로 알려 주며 엔진 스냅샷이 복구한다.
# 이 파일은 tools/gen_service_scripts.py 로 만든다. 고칠 때는 생성기를 고치고 다시 만든다.
set -u
export LC_ALL=C
shopt -s nullglob

UNIT_PATTERNS=("finger.service" "finger.socket" "fingerd.service")
PKGS=("finger-server" "fingerd" "efingerd" "cfingerd")
XINETD=("finger")
INETD=("finger")
GUARD_UNITS=()
GUARD_EXPORTS=""
LEFTOVER=()
INETD_CONF=/etc/inetd.conf
XINETD_DIR=/etc/xinetd.d

state() { printf '%s|%s\n' "$1" "$2"; }
have() { command -v "$1" >/dev/null 2>&1; }

pkg_any() {    # 0=설치됨 1=미설치 2=판별 불가
  local p
  if have rpm; then for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif have dpkg; then for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
  fi
  return 2
}

# ---- 존재하는 유닛 / xinetd 파일 / inetd 줄 수집 ----
units=()
if have systemctl; then
  for pat in "${UNIT_PATTERNS[@]}"; do
    while read -r u _; do
      [ -n "$u" ] && case "$u" in *@.service) ;; *) units+=("$u") ;; esac
    done < <(systemctl list-unit-files "$pat" --no-legend 2>/dev/null)
  done
  mapfile -t units < <(printf '%s\n' "${units[@]}" | sort -u | sed '/^$/d')
fi
xfiles=()
for n in "${XINETD[@]}"; do [ -f "$XINETD_DIR/$n" ] && [ ! -L "$XINETD_DIR/$n" ] && xfiles+=("$XINETD_DIR/$n"); done
inetd_on=0
if [ -f "$INETD_CONF" ] && [ ! -L "$INETD_CONF" ] && [ "${#INETD[@]}" -gt 0 ]; then
  pat=$(IFS='|'; echo "${INETD[*]}")
  grep -Eq "^[[:space:]]*($pat)[[:space:]]" "$INETD_CONF" && inetd_on=1
fi

unit_on() {    # 켜져 있으면(부팅 시 시작 또는 동작 중) 0
  local en ac
  en=$(systemctl is-enabled "$1" 2>/dev/null); ac=$(systemctl is-active "$1" 2>/dev/null)
  [ "$en" = masked ] && return 1
  [ "$ac" = active ] || [ "$en" = enabled ] || [ "$en" = enabled-runtime ]
}
xinetd_on() { grep -Eiq '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no' "$1"; }

bad_units=(); bad_xfiles=(); bad_info=()
scan_bad() {
  bad_units=(); bad_xfiles=(); bad_info=()
  local u f
  for u in "${units[@]}"; do
    if unit_on "$u"; then bad_units+=("$u"); bad_info+=("유닛 $u: 부팅=$(systemctl is-enabled "$u" 2>/dev/null) 동작=$(systemctl is-active "$u" 2>/dev/null)"); fi
  done
  for f in "${xfiles[@]}"; do xinetd_on "$f" && { bad_xfiles+=("$f"); bad_info+=("xinetd 설정 $f: disable = no"); }; done
  [ "$inetd_on" -eq 1 ] && bad_info+=("inetd 설정 $INETD_CONF: 대상 서비스 줄이 활성화되어 있음")
}

# 패키지가 없을 때: 관련 설정이 남아 있으면 점검 필요(MANUAL), 아무것도 없으면 해당없음(NA)
leftover() { local p f; for p in "$@"; do for f in $p; do [ -e "$f" ] || continue
  if [ -d "$f" ]; then [ -n "$(ls -A "$f" 2>/dev/null)" ] && echo "$f"
  elif [ -f "$f" ] && grep -Eqv '^[[:space:]]*(#|;|$)' "$f" 2>/dev/null; then echo "$f"; fi; done; done; }

if [ "${#units[@]}" -eq 0 ] && [ "${#xfiles[@]}" -eq 0 ] && [ "$inetd_on" -eq 0 ]; then
  case "${1:-}" in check|list|apply)
    pkg_any "${PKGS[@]}"; rc=$?
    if [ "$rc" -eq 0 ]; then state GOOD "패키지는 설치되어 있으나 활성 서비스 유닛/설정이 없음"; exit 0; fi
    l=$(leftover "${LEFTOVER[@]}" | head -5 | tr '\n' ' ')
    if [ -n "${l// /}" ]; then state MANUAL "대상 패키지는 설치되어 있지 않으나 관련 파일이 남아 있습니다(점검 필요): $l"
    else state NA "대상 서비스/패키지가 설치되어 있지 않고 관련 파일도 없어 점검 대상이 아닙니다"; fi
    exit 0 ;;
  esac
fi

# 다른 서비스가 쓰고 있을 수 있으면 자동 판단하지 않는다
guard_hit=""
for g in "${GUARD_UNITS[@]}"; do have systemctl && unit_on "$g" 2>/dev/null && guard_hit="$g"; done
if [ -n "$GUARD_EXPORTS" ] && [ -f "$GUARD_EXPORTS" ] && grep -Evq '^[[:space:]]*(#|$)' "$GUARD_EXPORTS"; then guard_hit="$GUARD_EXPORTS 에 공유 설정"; fi

case "${1:-}" in
  list)
    for u in "${units[@]}"; do
      printf '@service\t%s\tenabled=%s\tactive=%s\n' "$u" "$(systemctl is-enabled "$u" 2>/dev/null | tr -c 'a-z\n-' '-' | head -1)" "$(systemctl is-active "$u" 2>/dev/null | tr -c 'a-z\n-' '-' | head -1)"
    done
    for f in "${xfiles[@]}"; do printf '%s\txinetd 설정\n' "$f"; done
    [ "$inetd_on" -eq 1 ] && printf '%s\tinetd 설정\n' "$INETD_CONF"
    state GOOD "유닛 ${#units[@]}개, xinetd 파일 ${#xfiles[@]}개" ;;
  check)
    scan_bad
    if [ "${#bad_info[@]}" -gt 0 ]; then
      printf '%s\n' "${bad_info[@]}"
      if [ -n "$guard_hit" ]; then state MANUAL "활성 서비스가 있으나 다른 서비스가 사용 중일 수 있어 수동 확인 필요($guard_hit)"
      else state VULN "활성 서비스 ${#bad_info[@]}건 (기준: Finger 서비스가 비활성화)"; fi
    else
      state GOOD "대상 서비스가 모두 비활성화되어 있음"
    fi ;;
  apply)
    scan_bad
    xchanged=${#bad_xfiles[@]}
    [ -n "$guard_hit" ] && { state ERROR "다른 서비스가 사용 중일 수 있어 자동 조치하지 않습니다($guard_hit)"; exit 1; }
    for u in "${bad_units[@]}"; do
      systemctl disable --now "$u" >/dev/null 2>&1
      systemctl is-active "$u" >/dev/null 2>&1 && systemctl stop "$u" >/dev/null 2>&1
    done
    for f in "${bad_xfiles[@]}"; do sed -i -E 's/^([[:space:]]*disable[[:space:]]*=[[:space:]]*)[Nn][Oo]/\1yes/' "$f"; done
    inetd_changed=0
    if [ "$inetd_on" -eq 1 ]; then
      inetd_changed=1
      pat=$(IFS='|'; echo "${INETD[*]}")
      sed -i -E "s/^([[:space:]]*($pat)[[:space:]])/#\1/" "$INETD_CONF"
      inetd_on=0; grep -Eq "^[[:space:]]*($pat)[[:space:]]" "$INETD_CONF" && inetd_on=1
    fi
    scan_bad
    if [ "${#bad_info[@]}" -gt 0 ]; then printf '%s\n' "${bad_info[@]}"; state ERROR "조치 후에도 ${#bad_info[@]}건이 남아 있음"; exit 1; fi
    note=""
    if [ "$xchanged" -gt 0 ] || [ "$inetd_changed" -eq 1 ]; then
      for u in xinetd.service inetd.service openbsd-inetd.service; do
        have systemctl && systemctl is-active "$u" >/dev/null 2>&1 && systemctl reload "$u" >/dev/null 2>&1 && note=" (재적용: reload $u)"
      done
    fi
    state GOOD "조치 완료: 서비스 비활성화$note" ;;
  *)
    echo "usage: U-34.sh check|apply|list" >&2; exit 2 ;;
esac
