"""detect_os.sh를 실행해 OS 정보를 읽고, 지원 수준과 실행 정책을 판정한다.

단독 실행하면 판별 결과를 출력한다:  python3 os_info.py
테스트용:  python3 os_info.py --os-release /path/to/os-release
"""
import json
import subprocess
import sys
from pathlib import Path

# 검증이 끝난 OS는 여기에서 관리한다 (항목별 supported_os 와는 별개의 전체 정책)
SUPPORTED_KEYS = {"rocky9", "ubuntu24", "ubuntu26"}  # 실제 VM 으로 검증 완료: 전체 기능 (점검 + 조치)
EXTENDED_KEYS = {"rocky10", "ubuntu22"}  # 점검 허용, 조치는 항목별로 검증된 경우만 (예시값)

# 화면 문구는 코드 곳곳에 쓰지 않고 한곳에 모아둔다 (다국어 확장 대비)
MESSAGES = {
    "ko": {
        "root_required": "root 권한이 필요합니다. sudo로 다시 실행하세요.",
        "supported": "지원 환경입니다. 모든 기능을 사용할 수 있습니다.",
        "extended": "확장 테스트 환경입니다. 검증되지 않은 항목은 점검만 가능합니다.",
        "unsupported": "지원하지 않는 환경입니다. 읽기 전용 진단만 가능합니다.",
        "unknown": "OS를 판별하지 못했습니다. 읽기 전용 진단만 가능합니다.",
    }
}


class OSDetectError(RuntimeError):
    """detect_os.sh 실행 또는 결과 해석에 실패했을 때 발생한다."""


def resource_path(rel):
    """PyInstaller 실행 파일 안에서도, 개발 중에도 같은 방식으로 파일 경로를 찾는다."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base / rel


# 지원 OS 계열과 주 버전. 같은 계열·비슷한 버전은 같은 스크립트로 점검·조치한다(우분투는 전용 스크립트 우선).
FAMILIES = {"rocky": {9, 10}, "centos": {9, 10}, "ubuntu": {20, 22, 24, 26}}


def family_ok(info):
    """FAMILIES 에 해당하는 OS 인지(조치까지 허용). 버전이 목록에 없으면 False."""
    try:
        return int(str(info.get("os_version_major") or "0")) in FAMILIES.get(info.get("os_id"), ())
    except ValueError:
        return False


def classify(info):
    """OS 정보를 supported / extended / unsupported / unknown 으로 분류한다."""
    if not info.get("detect_ok"):
        return "unknown"          # 추측하지 않는다
    key = info.get("os_key")
    if key in SUPPORTED_KEYS:
        return "supported"
    if key in EXTENDED_KEYS or family_ok(info):
        return "extended"
    return "unsupported"


def policy(info):
    """분류 결과에 따라 엔진이 허용할 동작을 정한다.

    fix=True 는 '전체 조치 허용'이다. extended 환경에서는 기본적으로 조치를 막고,
    항목 정의의 fix_supported_os 에 해당 os_key 가 적혀 있는 항목만 엔진이 따로 허용한다.
    """
    if not info["is_root"]:
        return {"run": False, "fix": False, "reason": "root_required"}
    level = info["support_level"]
    # 테스트용 OS 대체(--os-release)가 켜져 있으면 실제 OS가 아니므로 조치는 항상 막는다
    if info.get("os_override"):
        return {"run": True, "fix": False, "reason": level}
    return {"run": True, "fix": level == "supported", "reason": level}


def detect_os(script="scripts/detect_os.sh", os_release=None, timeout=10):
    # 실행 권한 비트에 의존하지 않도록 bash 로 직접 실행한다 (번들 파일 대응)
    cmd = ["bash", str(resource_path(script))]
    if os_release:
        cmd += ["--os-release", str(os_release)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise OSDetectError(f"detect_os.sh 실행 실패: {e}") from e
    if r.returncode != 0:
        raise OSDetectError(f"detect_os.sh 오류(코드 {r.returncode}): {r.stderr.strip()}")
    try:
        info = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        raise OSDetectError(f"detect_os.sh 출력 해석 실패: {e}") from e

    info["support_level"] = classify(info)
    info["warnings"] = [w.removeprefix("warn: ").strip()
                        for w in r.stderr.splitlines() if w.strip()]
    info["policy"] = policy(info)
    return info


def main(argv):
    os_release = argv[2] if len(argv) >= 3 and argv[1] == "--os-release" else None
    msg = MESSAGES["ko"]
    try:
        info = detect_os(os_release=os_release)
    except OSDetectError as e:
        print(f"[오류] {e}", file=sys.stderr)
        return 1

    print(f"OS        : {info['os_name'] or '알 수 없음'} ({info['os_key']})")
    print(f"커널/구조 : {info['kernel']} / {info['arch']}")
    print(f"호스트    : {info['hostname']}")
    print(f"패키지    : {info['pkg_manager']}, 서비스: {info['init_system']}")
    print(f"SELinux   : {info['selinux']}, firewalld: {info['firewalld']}")
    for w in info["warnings"]:
        print(f"[경고] {w}")

    pol = info["policy"]
    if not pol["run"]:
        print(f"[중단] {msg[pol['reason']]}")
        return 1
    print(f"[판정] {msg[pol['reason']]}")
    print(f"조치 허용: {'예' if pol['fix'] else '아니오 (점검만)'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
