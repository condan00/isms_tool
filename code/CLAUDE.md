# CLAUDE.md — ISMS 점검·조치 도구

KISA 「2026 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드」(주통2026) Unix 서버 항목을 점검하고, 선택한 취약 항목을 조치·복구하는 도구. 개인 취업 포트폴리오 + 대학 3차 프로젝트 결과물이다. 대상 OS는 **Rocky Linux 9(주 대상)**, Rocky 10·Ubuntu는 확장 테스트 대상.

## 구조
```
main.py                  진입점(CLI 옵션 + 대화형 TUI)
os_info.py               시작 시 OS 판별 → 지원 수준(supported/extended/unsupported/unknown), root 여부
scripts/detect_os.sh     OS 정보를 JSON 한 줄로 출력 (읽기 전용)
scripts/items/U-xx.sh    항목별 점검·조치 스크립트 (계약: docs/SCRIPT_CONTRACT.md)
scripts/ubuntu/items/    우분투 전용 스크립트(U-02,03,66). OS 가 ubuntu/debian 이면 같은 이름이 있을 때 이것을 우선 실행(runner.script_path). tools/gen_ubuntu_scripts.py 로 생성
data/items.json          항목 정의 (tools/xlsx_to_items.py 가 엑셀에서 생성)
data/guides.json         항목별 조치 가이드 블록 (items.json 과 같은 폴더에서 자동으로 합친다)
../tools/gen_perm_scripts.py 고정 파일 목록 항목(U-18,19,20,21,22,63) 스크립트 생성기
isms/engine.py           점검 → 재점검 → 스냅샷 → 조치 → 재점검 → 자동 원복, 동시 실행 잠금
isms/runner.py           스크립트 실행·출력 파싱 (환경 변수 최소화, 시간 제한, 경로 신뢰 검사)
isms/snapshot.py         날짜별 스냅샷 생성·복구 (해시 검증)
isms/guide.py            조치 권고 가이드 생성
isms/report.py           JSON 원본 → HTML/TXT/CSV/XLSX 변환, isms-report/<yy-mm-dd_hh-mm>/ 저장(save_run)
isms/guidefiles.py       스크립트로 처리 안 된 항목의 가이드 → isms-guid/<yy-mm-dd_hh-mm>/U-XX_(제목)_guid.txt
isms/tui.py              questionary + rich 체크박스 UI (엔진을 호출만 한다)
isms/messages.py         화면 문구는 전부 여기 (코드에 한글 문구를 직접 쓰지 않는다)
isms/util.py             경로 신뢰 검사, 0600 쓰기, 마스킹, 감사 로그, sudo 사용자 처리
tests/test_engine.py     pytest
```
엔진은 화면을 모르고, TUI/CLI는 엔진을 호출만 한다. 이 경계를 유지한다.

## 명령
```
pip install -r requirements-dev.txt
python3 -m pytest tests -q                 # 변경 후 항상 실행. 전부 통과해야 한다
sudo ISMS_ALLOW_UNTRUSTED=1 python3 main.py   # 개발 중 실행 (스크립트 소유자가 root 가 아니므로)
bash build.sh                               # 단일 실행 파일: 도구 폴더 옆에 isms_run (Rocky 9 에서, 일반 계정으로. root 소유로 설치하려고 sudo 암호를 한 번 물음)
```
`ISMS_ALLOW_UNTRUSTED=1` 은 개발용이다. 코드, 문서, 예시 어디에도 운영 설정으로 권하지 않는다.

## 절대 지킬 규칙 (보안 도구이므로)
**점검·조치 스크립트**
- `check` 는 읽기 전용. 시스템을 바꾸는 명령 금지.
- `apply` 는 최소 변경만. **백업·복구 코드를 스크립트에 넣지 않는다**(엔진 스냅샷이 담당). 스크립트가 바꾸는 파일은 `data/items.json` 의 `touches.files` 에 전부 적는다. 빠지면 복구가 안 된다.
- 스크립트 안에서 `sudo` 사용 금지(이미 root 로 실행된다).
- `rm`, `userdel`, `chmod -R`, 패키지 설치·삭제, 대량 변경 금지 → 그런 항목은 `type: guide` 로 두고 목록·권고만 출력.
- 권한 판정은 `==` 비교가 아니라 "허용 범위를 넘는 비트" 로 한다(이미 더 엄격하면 양호).
- 출력 마지막 줄은 `STATE|근거`. 비밀번호·community 문자열 같은 값은 근거에 넣지 않는다.
- 로그인을 막을 수 있는 항목(U-01, 02, 03, 06)은 `approve`(확인 후 적용) 유지, 적용 전 문법 검증(`sshd -t` 등) 포함.

**엔진/파이썬**
- 스크립트 경로는 JSON 이 아니라 항목 코드(`^[A-Z]{1,4}-\d{2}$`)로만 만든다.
- 파일 쓰기는 `util.write_private`(0600, `O_EXCL|O_NOFOLLOW`, 덮어쓰기 없음) 사용. 리포트는 sudo 사용자 권한으로 낮춰 쓴다(`as_user`). 스냅샷·감사 로그는 root 전용(0700/0600) 유지.
- 리포트에 들어가는 값은 HTML 이스케이프, CSV/XLSX 는 수식 주입 방지(`_safe_cell`), 민감 값은 `mask_text`.
- 조치는 os_info.FAMILIES(rocky/centos 9·10, ubuntu 20·22·24·26)에 해당할 때만(그 밖은 점검만). 조치는 항목의 `fix_supported_os` 에 그 OS 가 있을 때만. `--os-release` 테스트 모드에서는 조치 금지.
- **실제 Rocky 9 VM에서 취약→조치→양호→복구를 검증하기 전에는 `fix_supported_os` 에 OS 를 추가하지 않는다.**
- 새 기능은 테스트를 같이 추가한다(특히 보안 관련: 링크 바꿔치기, 손상된 백업, 권한 복구).

## 항목 유형 (data/items.json 의 type)
| type | 동작 | 엑셀 적용방법 |
|---|---|---|
| auto | 취약이면 스냅샷 후 자동 적용 | 1~4 |
| approve | TUI 에서 확인 후 적용 | 1~4 중 위험 항목 |
| guide | 직접 적용하지 않고 점검 + 가이드만 | 5, 6, 7 (엑셀 쉘스크립트 X 포함) |

엑셀 열 의미: 쉘스크립트 가능=도구가 직접 적용하면 O / 가이드 작성 가능 / 백업 가능(O=100% 원복, △=일부·목록 저장, X=불가, ?=가변) / 패키지 확인 필요(대상 서비스·패키지가 기본 설치가 아닐 수 있어 설치 여부 확인) / 적용방법 1~7. `?` 는 환경·상황에 따라 달라 일부러 비워 둔 값이다. 전체 파일 검색 항목(U-15, 23, 25, 26)은 `heavy: true`(기본 선택에서만 제외)이고 `?` 이므로 check+apply+list 를 만든다(승인 후 적용). U-22 는 엑셀 재검토로 `?`.

## 흐름 / 출력 규칙
- 메뉴: 점검 및 조치(점검 → 취약 있으면 "이어서 조치?" → 전체 / 조치 필수(엑셀 쉘스크립트 가능=O, 이번에 취약) / 취약 중 선택) · 이전 결과 · 복구.
- 출력: 형식 기본 json+txt, 범위 vuln(취약·수동점검) / good(성공) / all. 화면 표는 양호 포함 전체.
- 결과 폴더는 isms 패키지 폴더 옆 `isms-report/`, `isms-guid/` (실행 파일 빌드 시 실행 파일 옆). sudo 사용자 권한으로 쓰고, 못 쓰면 사용자 홈으로 대체.

## 현재 상태 / 해야 할 일
- 구현됨: 엔진, 스냅샷·복구, TUI/CLI, 리포트 5종, OS 판별, sudo 사용자 소유 저장, 단위 테스트 26개.
- **스크립트 완료: 파일 소유자·권한 묶음 U-16,17,18,19,20,21,22,24,31,37,63,67** (check/apply/list + guides.json, 샌드박스 확인. Rocky 9 VM 검증은 아직). 엑셀 재검토로 U-05,08,10,14,22,36,67 도 ? 가 되어 apply 가 있다(규칙은 docs/SCRIPT_CONTRACT.md 맨 아래). U-22 는 엑셀 재검토로 ? (확인 후 root:root, 644 이하로 조치).
- 엑셀 '패키지 확인 필요'=O 항목은 스크립트 맨 앞에서 패키지/유닛 설치 여부를 확인하고 없으면 NA (docs/SCRIPT_CONTRACT.md '패키지 확인'). 생성기 PKGS 참고.
- 항목 스크립트 규칙: 엑셀 O·? = check+apply+list+가이드, X = apply 제외. 남은 항목은 아래 묶음 순서로 만든다. 나머지는 `docs/SCRIPT_CONTRACT.md` 를 따라 묶음 단위로 만들고 VM 에서 검증한다: ① 파일 소유자·권한(U-18, 19, 22, 63 …) ② 설정 파일 값(U-01, 02, 03, 06, 13, 30 …) ③ 서비스 비활성화(U-34, 39, 41~44, 52 …) ④ 가이드 전용.
- `touches.files` 는 9개 항목만 초기값이 있다. 스크립트 구현 시 확정.
- `guide` 블록(요약/결정할 값/단계/확인/원복/주의)은 전부 비어 있다. 가이드 전용 항목부터 채운다. 가이드 원문(KISA)을 복사하지 말고 요약·재작성하고 `ref` 로 출처만 표기, 자리표시자는 `<...>` 형식.
- 미구현: 서비스 상태 복구(스냅샷은 파일 내용·권한·소유자만 복원), 전후 비교 외 이력 조회, 영어 UI(`messages.py` 에 `en` 추가), 오래된 스냅샷 자동 정리 호출.
- 일정: 최종 제출 12월. 우선순위는 상 40개 항목 → 중 18개 → 확장. 일정이 밀리면 줄이는 순서: 확장 → 중 항목 → 리포트 꾸미기. 백업·복구는 마지막까지 지킨다.

## 스타일
- 화면 문구·리포트는 한국어, 코드 식별자·주석은 영어 또는 간결한 한국어(기존 파일 스타일에 맞춘다).
- 항목 코드(U-01 등)는 가이드 그대로. 환경 의존 값(OS 버전, 패키지 경로)은 추측하지 말고 VM 에서 확인한 값만 쓴다. 확인 못 한 것은 "확인 필요"로 표시한다.
- 포트폴리오로 공개한다: 샘플 결과·스크린샷은 테스트 VM 결과만, 가이드 원문 복사 금지, 라이선스 있는 외부 코드 복사 금지.

## 가이드 수정
- 항목별 상세 가이드(점검 목적·보안 위협·판단 기준·점검/조치 방법·조치 영향)는 `tools/guides_part*.py` 에서 고치고 `python3 ../tools/gen_guides.py` 로 `data/guides.json` 을 다시 만든다.
- 엑셀 원본의 오타는 `isms/items.py` 의 `TYPOS` 로 불러올 때 고친다(예: 싱행→실행).

## 시험용 도구
- `tools/make_test_vm_vulnerable_rocky.sh(로키)/make_test_vm_vulnerable_ubuntu.sh(우분투) apply --yes-test-vm [--with-admin]` : 테스트 VM 을 항목별로 일부러 취약하게 만든다(기본으로 dnf 로 필요한 패키지까지 설치해 U-01~67 중 약 50개 항목을 취약하게 만든다. `--no-packages` 면 설치 없이 이미 있는 것만. undo 는 우리가 설치한 패키지도 제거. 제외: U-04, 08, 63, 64). `verify` 로 점검, `undo` 로 원복(/root/isms-vuln-seed/ 백업). 운영 서버 금지.
- 자동 조치가 불가능한(가이드 전용) 항목이 취약이면 화면·보고서에 `취약 (수동점검 필요)` 로 표시한다(`isms/messages.py` state_text).

## sudo 실행 시 "신뢰할 수 없는 스크립트 경로" 오류
- root 권한으로 실행하는 스크립트라 `scripts/` 와 안의 `.sh` 는 소유자가 root 이고 그룹·기타 쓰기 권한이 없어야 한다(압축을 풀면 일반 사용자 소유로 풀려 걸린다).
- 해결: `sudo chown -R root:root <도구 폴더> && sudo chmod -R go-w <도구 폴더>`. 실행 시작 때 한 번 검사해 이 명령을 안내한다.

- `isms_lite_check.sh`(도구 폴더 맨 위)는 `tools/gen_lite_check.py` 가 만든 단독 실행 점검 스크립트다. 점검 규칙은 `code/scripts` 에서 가져오므로 직접 고치지 않는다(고친 뒤 생성기를 다시 실행, 테스트가 검사). 시스템을 바꾸지 않으며, 출력 형식(`호스트  U-XX  근거`, 마지막 줄 `vuln:`)은 배포 도구가 읽으므로 바꾸지 않는다.
