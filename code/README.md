# ISMS 점검·조치 도구 (주통2026 Unix 서버)

Python 엔진 + 체크박스 TUI + 항목별 쉘 스크립트로 구성된 점검·조치 자동화 도구.

```
main.py ─ isms/engine.py ─ runner.py ─ scripts/items/U-xx.sh   (점검·조치, 계약: docs/SCRIPT_CONTRACT.md)
   │          ├ snapshot.py   조치 전 날짜별 스냅샷 / 복구
   │          ├ guide.py      조치 권고 가이드 생성
   │          └ report.py     JSON·HTML·TXT·CSV·XLSX 출력
   └ tui.py (questionary + rich)
os_info.py + scripts/detect_os.sh   실행 시작 시 OS 판별 → 지원 수준·조치 허용 여부 결정
```

## 실행
```
sudo python3 main.py                                   # 대화형 TUI
sudo python3 main.py --scan-only --severity 상 --format html,json --scope vuln
sudo python3 main.py --fix --ids U-16,U-18 --yes       # 비대화형 조치(U-01,02,03,06은 --allow-risky 필요)
sudo python3 main.py --list-snapshots
sudo python3 main.py --restore 20261113-101500 --yes
```
데이터(스냅샷, 감사 로그, 리포트)는 `/var/lib/isms-tool`(0700)에 저장된다. `--data-dir` 로 변경.

## 항목 정의 만들기
`python3 ../tools/xlsx_to_items.py <가이드 엑셀>` → `data/items.json`. 이후 항목별로 `touches.files`, `guide` 블록을 채운다.

## 안전장치
- 지원 OS(`rocky9`, `ubuntu24`, `ubuntu26`)가 아니면 점검만 허용. 항목별 `fix_supported_os` 에 있는 OS 에서만 조치.
- 조치 직전 재점검 → 취약일 때만 조치 → 스냅샷 → 조치 → 재점검. 실패하면 해당 항목 파일 자동 원복.
- 스크립트 경로 신뢰 검사(root 소유, 그룹/기타 쓰기 불가, 심볼릭 링크 불가). 개발 중에만 `ISMS_ALLOW_UNTRUSTED=1`.
- 결과 파일 0600, 덮어쓰기 없음, 민감 값 마스킹, HTML 이스케이프, CSV/XLSX 수식 주입 방지.

## 테스트 / 빌드
```
pip install -r requirements-dev.txt && python3 -m pytest tests -q
bash build.sh     # Rocky 9 에서 일반 계정으로 실행 → 도구 폴더 옆에 isms_run 생성. 실행: sudo ./isms_run
```
