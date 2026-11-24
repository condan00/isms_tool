#!/usr/bin/env python3
"""파일 소유자·권한 묶음 중 '고정 파일 목록' 항목(U-18,19,20,21,22,63)의 스크립트를 만든다.

같은 틀(check / apply / list)을 항목마다 복사하다 생기는 실수를 막기 위한 생성기다.
생성된 스크립트는 단독으로 동작한다(다른 파일을 source 하지 않는다).
사용: python3 tools/gen_perm_scripts.py [출력 폴더(기본 scripts/items)]
"""
import sys
from pathlib import Path

# id: (제목, 파일 패턴들, 허용 소유자, 최대 권한, apply 포함 여부, 기준 설명)
# PKGS: 엑셀 "패키지 확인 필요"=O 인 항목. 이 중 하나라도 설치되어 있어야 점검한다(없으면 해당없음).
LABELS = {"U-20": ("xinetd/inetd", '"/etc/xinetd.conf" "/etc/xinetd.d" "/etc/inetd.conf"'),
          "U-21": ("rsyslog/syslog-ng", '"/etc/rsyslog.conf" "/etc/rsyslog.d" "/etc/syslog-ng/syslog-ng.conf" "/etc/syslog.conf"')}
PKGS = {"U-20": ["xinetd", "openbsd-inetd"], "U-21": ["rsyslog", "syslog-ng"]}
SPECS = {
    "U-18": ("/etc/shadow 파일 소유자 및 권한 설정", ["/etc/shadow"], ["root"], "400", True, "소유자 root, 권한 400 이하"),
    "U-19": ("/etc/hosts 파일 소유자 및 권한 설정", ["/etc/hosts"], ["root"], "644", True, "소유자 root, 권한 644 이하"),
    "U-20": ("/etc/(x)inetd.conf 파일 소유자 및 권한 설정",
             ["/etc/inetd.conf", "/etc/xinetd.conf", "/etc/xinetd.d/*"], ["root"], "600", True,
             "소유자 root, 권한 600 이하 (xinetd.d 는 안의 파일만, 하위 폴더는 대상 아님)"),
    "U-21": ("/etc/(r)syslog.conf 파일 소유자 및 권한 설정",
             ["/etc/rsyslog.conf", "/etc/syslog.conf", "/etc/syslog-ng/syslog-ng.conf"], ["root", "bin", "sys"], "640", True,
             "소유자 root(또는 bin, sys), 권한 640 이하"),
    "U-22": ("/etc/services 파일 소유자 및 권한 설정", ["/etc/services"], ["root"], "644", True,
             "소유자 root, 권한 644 이하 (엑셀 쉘스크립트 가능=?: 확인 후 소유자는 root 로, 권한은 644 이하로 조치)"),
    "U-63": ("sudo 명령어 접근 관리", ["/etc/sudoers"], ["root"], "640", True, "소유자 root, 권한 640 이하"),
}

TEMPLATE = r'''#!/bin/bash
# {id} {title}
# 기준: {criteria}
# 계약: bash {id}.sh check|{apply_word}list  →  stdout 마지막 줄 "STATE|근거" (docs/SCRIPT_CONTRACT.md)
# 권한은 숫자 == 비교가 아니라 '허용 범위를 넘는 비트'로 판정한다(이미 더 엄격하면 양호).
# 이 파일은 tools/gen_perm_scripts.py 로 만든다. 고칠 때는 생성기를 고치고 다시 만든다.
set -u
export LC_ALL=C
shopt -s nullglob

PATTERNS=({patterns})
OWNERS=" {owners} "
MAX_MODE={max_mode}

state() {{ printf '%s|%s\n' "$1" "$2"; }}
# 열어 둔 파일 기술자(fd)로 소유자/권한을 바꿔, 점검~조치 사이에 심볼릭 링크로 바꿔치기해도 엉뚱한 파일을 건드리지 않는다
safe_fix() {{ local f=$1 own=${{2:-}} mod=${{3:-}} a b rc=0
  [ -L "$f" ] && return 1
  {{ exec 9<"$f"; }} 2>/dev/null || return 1
  a=$(stat -Lc '%d:%i' /proc/self/fd/9 2>/dev/null); b=$(stat -c '%d:%i' "$f" 2>/dev/null)
  if [ -n "$a" ] && [ "$a" = "$b" ]; then
    [ -n "$own" ] && {{ chown "$own" /proc/self/fd/9 || rc=1; }}
    [ -n "$mod" ] && {{ chmod "$mod" /proc/self/fd/9 || rc=1; }}
  else rc=1; fi
  exec 9<&-; return $rc; }}
{pkg_block}
targets=(); links=0
for f in "${{PATTERNS[@]}}"; do
  if [ -L "$f" ]; then links=$((links + 1)); continue; fi
  [ -f "$f" ] && targets+=("$f")
done

bad=(); bad_info=()
scan_bad() {{
  bad=(); bad_info=()
  local f owner mode over
  for f in "${{targets[@]}}"; do
    read -r owner mode < <(stat -c '%U %a' "$f")
    over=$(( 8#$mode & ~8#$MAX_MODE & 8#7777 ))
    case "$OWNERS" in *" $owner "*) o_ok=1 ;; *) o_ok=0 ;; esac
    if [ "$o_ok" -ne 1 ] || [ "$over" -ne 0 ]; then
      bad+=("$f"); bad_info+=("$f"$'\t'"소유자=$owner 권한=$mode")
    fi
  done
}}

if [ "${{#targets[@]}}" -eq 0 ]; then
  case "${{1:-}}" in check|list|apply)
    if [ "$links" -gt 0 ]; then state MANUAL "대상이 심볼릭 링크입니다(수동 확인)"; else state NA "대상 파일이 없습니다"; fi
    exit 0 ;;
  esac
fi

case "${{1:-}}" in
  list)
    for f in "${{targets[@]}}"; do
      read -r owner mode < <(stat -c '%U %a' "$f"); printf '%s\t소유자=%s 권한=%s\n' "$f" "$owner" "$mode"
    done
    state GOOD "${{#targets[@]}}개 파일"
    ;;
  check)
    scan_bad
    if [ "${{#bad[@]}}" -gt 0 ]; then
      printf '%s\n' "${{bad_info[@]}}"
      state VULN "${{#bad[@]}}개 파일이 기준 미달 (기준: {short})"
    else
      state GOOD "${{#targets[@]}}개 파일 모두 기준 충족"
    fi
    ;;
{apply_block}  *)
    echo "usage: {id}.sh check|{apply_word}list" >&2; exit 2 ;;
esac
'''

APPLY = r'''  apply)
    # 스냅샷은 엔진이 이미 만들었다(list 로 알려 준 파일). 기준 미달 파일만 최소 변경한다.
    scan_bad
    for f in "${bad[@]}"; do
      read -r owner mode < <(stat -c '%U %a' "$f")
      case "$OWNERS" in *" $owner "*) ;; *) safe_fix "$f" root ;; esac
      over=$(( 8#$mode & ~8#$MAX_MODE & 8#7777 ))
      [ "$over" -ne 0 ] && safe_fix "$f" "" "$(printf '%o' $(( 8#$mode & 8#$MAX_MODE )))"
    done
    scan_bad
    if [ "${#bad[@]}" -gt 0 ]; then state ERROR "조치 후에도 ${#bad[@]}개 파일이 기준 미달"; exit 1; fi
    state GOOD "조치 완료: ${#targets[@]}개 파일 기준 충족"
    ;;
'''


PKG_BLOCK = r'''
# 패키지 설치 여부: 0=설치됨, 1=미설치, 2=판별 불가(rpm/dpkg 없음 → 그대로 점검)
pkg_any() {
  local p
  if command -v rpm >/dev/null 2>&1; then
    for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && return 0; done; return 1
  elif command -v dpkg >/dev/null 2>&1; then
    for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -q '^Status: install ok installed' && return 0; done; return 1
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
if [ "${1:-}" = check ] || [ "${1:-}" = apply ] || [ "${1:-}" = list ]; then
  pkg_gate "__LABEL__" "__PKGS__" __LEFT__
fi
'''


def render(iid):
    title, pats, owners, mx, has_apply, crit = SPECS[iid]
    short = f"{'/'.join(owners)}, {mx} 이하"
    pkg_block = PKG_BLOCK.replace("__LABEL__", LABELS[iid][0]).replace("__LEFT__", LABELS[iid][1]).replace("__PKGS__", " ".join(PKGS[iid])) if iid in PKGS else ""
    return TEMPLATE.format(pkg_block=pkg_block, id=iid, title=title, criteria=crit, patterns=" ".join(pats), owners=" ".join(owners),
                           max_mode=mx, short=short, apply_block=APPLY if has_apply else "",
                           apply_word="apply|" if has_apply else "")


def main(out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    for iid in SPECS:
        (out / f"{iid}.sh").write_text(render(iid), encoding="utf-8")
        print("생성:", out / f"{iid}.sh")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "code" / "scripts" / "items")
