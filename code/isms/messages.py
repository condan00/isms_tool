"""화면에 출력되는 모든 문구를 한곳에 모은다. 영어 등 추가 언어는 MESSAGES 에 키만 추가하면 된다."""

LANG = "ko"

MESSAGES = {
    "ko": {
        "title": "ISMS 점검·조치 도구 (주통2026 Unix)",
        "need_root": "root 권한이 필요합니다. sudo 로 다시 실행하세요.",
        "env_ok": "지원 환경입니다. 점검과 조치를 모두 사용할 수 있습니다.",
        "env_ext": "호환 환경입니다. 같은 계열이라 점검과 조치를 사용할 수 있지만 Rocky 9·Ubuntu 24·26 외에는 검증 전이니 시험 서버에서 먼저 확인하세요.",
        "env_unsupported": "지원하지 않는 환경입니다. 읽기 전용 점검만 가능합니다.",
        "env_unknown": "OS를 판별하지 못했습니다. 읽기 전용 점검만 가능합니다.",
        "menu_main": "무엇을 할까요?",
        "menu_scan_fix": "1. 점검 및 조치",
        "menu_last": "2. 이전 점검 결과 보기",
        "menu_restore": "3. 스냅샷으로 복구",
        "menu_quit": "종료",
        "pick_items": "점검할 항목을 선택하세요 (스페이스: 선택, a: 전체, 엔터: 확인)",
        "pick_preset": "점검 범위를 선택하세요",
        "preset_all": "전체 항목",
        "preset_cat": "분류별 선택",
        "preset_custom": "항목 직접 선택",
        "pick_fix": "조치할 항목을 선택하세요 (취약 항목만 표시)",
        "no_vuln": "조치할 취약 항목이 없습니다.",
        "heavy_warn": "전체 파일 검색 항목은 시간이 오래 걸릴 수 있어 기본 선택에서 제외했습니다.",
        "confirm_apply": "선택한 {n}개 항목을 조치합니다. 조치 전 스냅샷을 만듭니다. 계속할까요?",
        "warn_ssh_session": "[yellow]현재 SSH(원격) 세션으로 접속 중입니다. 기존 연결은 유지되지만 새 연결부터 설정이 적용되므로, 다른 터미널로 로그인되는지 꼭 확인하세요.[/yellow]",
        "confirm_ssh": "SSH/PAM 관련 항목이 포함되어 있습니다. 별도 SSH 세션을 열어 두었습니까?",
        "snapshot_made": "스냅샷 생성: {id}",
        "pick_format": "결과를 어떤 형식으로 저장할까요?",
        "pick_scope": "출력 범위를 선택하세요",
        "scope_vuln": "취약·수동점검 항목만",
        "scope_good": "성공(양호) 항목만",
        "scope_all": "전체",
        "ask_fix": "점검이 끝났습니다. 이어서 조치도 수행할까요?",
        "pick_fix_mode": "조치할 범위를 선택하세요",
        "fix_mode_required": "기본: 필수 항목(O)만 ({n}개)",
        "fix_mode_all": "전체: 필수(O) + 선택(?) 항목 ({n}개)",
        "fix_mode_group": "분류별 선택",
        "fix_mode_pick": "항목별 선택 (항목 코드를 보고 직접 고름)",
        "pick_group": "조치할 분류를 선택하세요 (스페이스: 선택, 엔터: 확인)",
        "group_opt": "[선택 항목도 적용] 위에서 고른 분류의 ? 항목도 함께 조치",
        "group_file": "파일 소유자·권한", "group_config": "설정 파일 값",
        "group_service": "서비스 비활성화", "group_guide": "가이드 전용 (직접 적용 안 함)",
        "group_guide_off": "도구가 적용하지 않습니다. 가이드 파일로 저장됩니다",
        "mark_opt": "?",
        "no_required": "이번 점검에서 취약으로 나온 해당 범위의 조치 항목이 없습니다.",
        "guide_note": "직접 조치가 필요한 취약 항목 {n}개는 가이드 파일로 저장합니다.",
        "saved_dir": "저장 폴더: {path}",
        "guide_saved": "조치 가이드 {n}개 저장: {path}",
        "saved": "저장됨: {path} ({size} bytes)",
        "scp_hint": "서버에서 내려받으려면: scp <사용자>@<서버>:{path} .",
        "pick_snapshot": "복구할 스냅샷(날짜)을 선택하세요",
        "no_snapshot": "복구할 스냅샷이 없습니다.",
        "confirm_restore": "스냅샷 {id} 시점으로 파일 {n}개를 복구합니다. 계속할까요?",
        "restore_done": "복구 완료: {ok}개 성공, {fail}개 실패",
        "cancelled": "취소했습니다.",
        "st_GOOD": "양호", "st_VULN": "취약", "st_MANUAL": "수동점검",
        "st_NA": "해당없음", "st_ERROR": "오류", "st_SKIP": "건너뜀",
        "st_FIXED": "조치됨", "st_FAILED": "조치 실패", "st_BLOCKED": "조치 불가",
        "type_auto": "자동 적용", "type_approve": "승인 후 적용", "type_guide": "가이드 안내",
        "sev_상": "상", "sev_중": "중", "sev_하": "하",
    }
}


def t(key, **kw):
    s = MESSAGES.get(LANG, MESSAGES["ko"]).get(key, key)
    return s.format(**kw) if kw else s


MANUAL_FIX_SUFFIX = " (수동점검 필요)"


def state_text(r, use_fix=False):
    """결과 한 건의 판정 표시. 자동 조치 대상이 아닌 항목(가이드 전용)이 취약이면 '취약 (수동점검 필요)' 로 표시한다."""
    st = (r.get("fix_state") if use_fix and r.get("fix_state") else r["state"])
    txt = t("st_" + st) if ("st_" + st) in MESSAGES["ko"] else st
    if st == "VULN" and r.get("type") == "guide":
        txt += MANUAL_FIX_SUFFIX
    return txt
