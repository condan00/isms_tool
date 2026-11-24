ISMS 점검·조치 도구 (KISA 주통2026 Unix 서버 / Rocky Linux 9)
=============================================================

어떤 화면으로 쓸지 고르세요. 둘 다 같은 엔진·같은 흐름(점검 -> 선택 조치 -> 조치 후 자동 재점검 -> 가이드/결과 저장 -> 스냅샷 복구)입니다.

1) 터미널(CLI) 로 쓰려면  ->  build.sh
     ./build.sh
     sudo ../isms_run            (isms_tool 폴더와 같은 위치에 isms_run 이 생김)

2) 마우스 클릭 화면(GUI) 으로 쓰려면  ->  build-GUI.py
     (tkinter 등 필요한 패키지는 자동 설치됩니다. 수동: Rocky sudo dnf install -y python3-tkinter / 우분투 sudo apt install -y python3-tk python3-venv)
     python3 build-GUI.py
     sudo ../isms_run_gui                    (데스크톱 화면에서 실행)
   - 화면이 안 뜨면(sudo 가 사용자 화면에 접속 못 함) 일반 계정으로 한 번:  xhost +SI:localuser:root
   - 빌드 없이 소스로 바로 실행:  python3 build-GUI.py --run   (점검·조치는 sudo 필요)
   - "이전 결과 보기", "스냅샷 복구" 등 모든 화면에 뒤로/취소 버튼이 있고 Esc 키로도 돌아갑니다.
     스냅샷 복구는 스냅샷 -> 항목 선택 -> 확인 순서이며 단계마다 뒤로 갈 수 있습니다.

3) 여러 서버에 돌려서 취약한 항목만 모으려면 (빌드 불필요, 파이썬 불필요, 점검만 하고 시스템은 바꾸지 않음)  ->  isms_lite_check.sh
     sudo bash isms_lite_check.sh            (터미널에서는 1.Rocky 2.Ubuntu 3.Windows 메뉴, Ansible 등 비대화형이면 OS 자동 판별. Windows 는 준비 중)
   - 취약한 항목만 서버 이름과 함께 한 줄씩 출력하고, 마지막 줄에 요약합니다:
         vm  U-02  비밀번호 정책 미충족 ...
         vm  U-18  1개 파일이 기준 미달 ...
         vm  vuln: U-02, U-18          (취약이 없으면  vm  vuln: X)
     점검 스크립트가 실패한 항목은  vm  U-XX  ERROR ...  로 표시합니다. 취약·오류가 있으면 종료 코드 1.
   - 옵션: 1|2|auto(번호 지정)  -v(모든 항목 출력)  --ids U-04,U-16(일부만)  --heavy(전체 파일 검색 항목 U-15,23,25,26 포함)
   - 이 파일 하나로 동작합니다(다른 파일 필요 없음). 58개 항목의 점검 명령이 파일 안에 들어 있으므로 isms_lite_check.sh 만 서버로 보내면 됩니다.
     항목 스크립트(code/scripts)를 고쳤다면 python3 tools/gen_lite_check.py 로 다시 만드세요(파일을 직접 고치지 마세요).
   - 조치·스냅샷 복구·가이드 생성은 위의 1), 2) 프로그램에만 있습니다.

빌드 결과 위치
  build.sh 와 build-GUI.py 는 같은 폴더(isms_tool 폴더의 바로 위, 즉 isms_tool 과 같은 열)에
  isms_run(CLI) / isms_run_gui(GUI) 를 만듭니다. isms-report/, isms-guid/ 도 같은 폴더에 생깁니다.

지원 OS (실행할 때 자동 판별, 점검과 조치 모두 가능)
  Rocky Linux 9 / 10, CentOS 9 / 10   공통 스크립트(scripts/items/)
  Ubuntu 20 / 22 / 24 / 26          scripts/ubuntu/items/ 의 우분투 전용 스크립트(U-02,U-03,U-66)를 먼저 쓰고,
                                     전용이 없는 항목은 공통 스크립트(rpm/dpkg 둘 다 처리)를 씁니다.
  Rocky 9 / Ubuntu 24 / Ubuntu 26 은 실제 VM 으로 검증해 '지원 환경'으로 표시되고, 나머지는 '호환 환경'(같은 계열이라 동작하지만 검증 전)으로 표시됩니다. 시험 서버에서 먼저 확인하세요.
  목록에 없는 OS(Rocky/CentOS 8, Ubuntu 18, Debian 등)는 점검만 가능합니다. 목록은 code/os_info.py 의 FAMILIES.
  우분투 전용 스크립트 수정: tools/gen_ubuntu_scripts.py 를 고치고 다시 실행

결과물 위치 (실행 파일이 있는 폴더 기준)
  isms-report/yy-mm-dd_hh-mm/   점검·조치 결과(JSON)
  isms-guid/yy-mm-dd_hh-mm/     항목별 가이드  U-XX_(제목)_guid.txt

폴더 구성
  readme.txt     이 파일
  build.sh       CLI 빌드
  build-GUI.py   GUI 빌드
  tools/         개발용 생성기(점검 스크립트·가이드 재생성) 및 엑셀 변환. 실행 파일에는 포함되지 않음
  code/          프로그램 본체(main.py=CLI, gui.py=GUI, isms/, scripts/, data/, docs/, tests/)
                 자세한 구조·스크립트 규약은 code/README.md, code/CLAUDE.md, code/docs/ 참고

테스트(개발용):  cd code && python3 -m pytest -q tests
