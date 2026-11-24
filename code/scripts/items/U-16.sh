#!/bin/bash
# U-16 /etc/passwd 파일 소유자 및 권한 설정 (기준: 소유자 root, 권한 644 이하)  -- 참고용 구현 예시
# 계약: bash U-16.sh check|apply  →  stdout 마지막 줄 "STATE|근거"
# 권한은 숫자 비교(==)가 아니라 '허용 범위를 넘는 비트'로 판정한다 (이미 더 엄격하면 양호).
set -u
export LC_ALL=C
TARGET=/etc/passwd
MAX_MODE=644

state() { printf '%s|%s\n' "$1" "$2"; }

[ -e "$TARGET" ] || { state NA "$TARGET 없음"; exit 0; }
[ -L "$TARGET" ] && { state MANUAL "$TARGET 가 심볼릭 링크입니다(수동 확인)"; exit 0; }

read -r owner mode < <(stat -c '%U %a' "$TARGET")
# 허용 범위를 넘는 비트 = (현재 모드) & ~(허용 모드)
over=$(( 8#$mode & ~8#$MAX_MODE & 8#7777 ))

is_vuln() { [ "$owner" != "root" ] || [ "$over" -ne 0 ]; }

case "${1:-}" in
  check)
    if is_vuln; then state VULN "소유자=$owner 권한=$mode (기준: root, $MAX_MODE 이하)"
    else state GOOD "소유자=$owner 권한=$mode"; fi
    ;;
  apply)
    # 스냅샷은 엔진이 이미 만들었다. 여기서는 필요한 변경만 한다.
    [ "$owner" != "root" ] && chown root "$TARGET"
    [ "$over" -ne 0 ] && chmod "$(printf '%o' $(( 8#$mode & 8#$MAX_MODE )))" "$TARGET"
    read -r owner mode < <(stat -c '%U %a' "$TARGET")
    over=$(( 8#$mode & ~8#$MAX_MODE & 8#7777 ))
    if is_vuln; then state ERROR "조치 후에도 기준 미충족: 소유자=$owner 권한=$mode"; exit 1
    else state GOOD "조치 완료: 소유자=$owner 권한=$mode"; fi
    ;;
  *)
    echo "usage: U-16.sh check|apply" >&2; exit 2 ;;
esac
