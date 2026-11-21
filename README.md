8bit 졸업 작품: AI 기반 네트워크 관리 시스템

8bit 졸업 작품으로 만든 AI 기반 네트워크 모니터링·보안 관제 시스템입니다. 직접 설치하고 실행해 보고 싶은 후배·학생을 위해 공개합니다.

📘 설치 가이드: https://angerdenny.github.io/8bit-graduation-project/guide.html

프로젝트 소개

네트워크 장비와 PC의 상태(CPU, 메모리, 트래픽, 응답 시간)를 한 화면에서 보고, AI(Isolation Forest)로 이상 징후를 감지해 경보를 만드는 관제 시스템입니다. 관리자는 경보를 확인하고 완화나 차단 같은 조치를 승인할 수 있습니다.

2022년 판교 데이터센터 화재로 대형 서비스가 멈춘 사례를 계기로 세 가지를 목표로 만들었습니다.

장애는 한 곳에서 시작해 전체로 번집니다.
사람이 확인하기 전에 이상을 먼저 감지해야 합니다.
관리 도구는 감시 대상과 분리되어 있어야 합니다.
주요 기능
실시간 트래픽과 장비 상태(CPU, 메모리) 모니터링
AI 기반 장애 위험 스코어와 이상 징후 알림
장비 핑 확인, 보안 로그, 알림 기록
교대 인수인계 기록과 공지
네트워크 토폴로지 맵과 구역(VLAN) 관리
장애 시뮬레이션으로 화면 동작 재현 (실제 장비에는 영향 없음)
기술 스택
영역	기술
서버	Python, FastAPI, SQLAlchemy, PyMySQL
인증	JWT (python-jose), passlib + bcrypt
수집·감시	Python, psutil, requests
AI	scikit-learn (Isolation Forest), numpy, joblib
화면	HTML, CSS (Tailwind CSS), JavaScript, lucide 아이콘
데이터베이스	MySQL 8.0
구성
로컬 실행 (기본)

내 PC 한 대에서 서버, DB, 수집기를 모두 실행합니다.

PC ── collector.py (CPU·메모리·트래픽 측정) ──┐
     pinger.py    (장비 핑 측정) ───────────┤
                                            ▼
브라우저 ── 대시보드 ── FastAPI 서버 (uvicorn, 내 PC) ── MySQL (netmon, 내 PC)
클라우드 실행 (선택)

서버와 DB를 인터넷의 호스팅 서비스에 올리고, 수집기는 PC에서 그 서버로 값을 보냅니다.

PC ── collector.py / pinger.py ──(인터넷)──┐
                                           ▼
브라우저 ── 대시보드 ── FastAPI 서버 (Render) ── MySQL (Aiven)
서버만 DB에 접속합니다.
수집기는 측정값을 서버 API로만 보냅니다. 보낼 주소는 .env의 BACKEND_URL로 정합니다. 로컬이면 내 PC 주소, 클라우드면 배포된 서버 주소입니다.
폴더 구조
8bit-graduation-project/
├─ docs/
│  ├─ guide.html            설치 가이드 (슬라이드, GitHub Pages)
│  └─ images/               가이드 사진
├─ public/
│  └─ index.html            대시보드 화면 (HTML, CSS, JavaScript)
├─ src/
│  ├─ ai/
│  │  └─ detector.py        이상 탐지 모델
│  └─ backend/
│     ├─ main.py            서버 시작, 로그인, 장비·구역 API
│     ├─ ai_routes.py       AI 경보, 조치 승인, 에이전트 API
│     ├─ agent_link.py      회원가입, 승인, PC 연결 코드, 측정값 API
│     ├─ sim_routes.py      장애 시뮬레이션
│     ├─ models.py          DB 모델 (SQLAlchemy)
│     ├─ database.py        DB 연결 설정
│     ├─ collector.py       PC 상태 측정 후 서버 전송
│     ├─ pinger.py          등록된 장비 핑 측정
│     ├─ agent.py           의심 프로세스 탐지
│     ├─ scanner.py         같은 네트워크 기기 탐색
│     ├─ agent_ai.py        차단 에이전트 (시연용)
│     ├─ seed_virtual_devices.py  시연용 가상 장비 생성·삭제
│     └─ .env.example       환경변수 이름 목록 (값 없음)
├─ migrations/
│  ├─ 001_client_uuid.sql   기기 식별자 컬럼 추가
│  └─ 002_ping_logs.sql     응답 시간 기록 테이블
├─ schema.sql               전체 테이블 생성
├─ requirements.txt         Python 패키지 목록
└─ README.md
설치 및 실행 (로컬, 내 PC에서)

자세한 설명과 사진은 설치 가이드에 있습니다. 요약은 다음과 같습니다.

1. 준비물
Python 3.10 이상
MySQL 8.0
Git
2. 코드 받기와 라이브러리 설치
powershell
git clone https://github.com/angerdenny/8bit-graduation-project.git
cd 8bit-graduation-project
pip install -r requirements.txt
3. .env 만들기

src/backend/.env.example을 복사해 src/backend/.env로 이름을 바꾸고 값을 채웁니다.

powershell
copy src\backend\.env.example src\backend\.env

JWT_SECRET과 AGENT_API_KEY는 아래 명령으로 각각 새로 만듭니다.

powershell
python -c "import secrets; print(secrets.token_hex(32))"

.env는 Git에 올리지 마세요. 저장소에는 값이 없는 .env.example만 있습니다.

4. 데이터베이스 준비
sql
CREATE DATABASE netmon CHARACTER SET utf8mb4;
powershell
mysql -u root -p netmon < schema.sql
mysql -u root -p netmon < migrations\001_client_uuid.sql
mysql -u root -p netmon < migrations\002_ping_logs.sql
5. 서버 3개 실행 (각각 다른 터미널, 모두 src\backend에서)
터미널	명령	정상 표시
1 서버	uvicorn main:app --host 0.0.0.0 --port 8000	Uvicorn running on ...
2 수집기	python collector.py	cpu=… ram=… 줄이 주기적으로 출력
3 핑	python pinger.py	등록된 기기를 5초마다 핑합니다
6. 브라우저 접속

http://127.0.0.1:8000/을 열고 **"노트북 로컬"**을 선택합니다. 회원가입 후 로그인하고, "내 PC 연결"에서 collector 창에 표시된 6자리 코드를 입력하면 장비가 연결됩니다.

화면 사용법 (요약)
대시보드: 실시간 트래픽, AI 위험 스코어, 장비 상태, 최근 알림을 한눈에 봅니다.
토폴로지: 장비를 구역(VLAN)별로 배치하고 연결을 봅니다.
알림: 경보를 눌러 상세 내용과 권장 조치를 확인합니다.
교대: 인수인계 내용과 공지를 기록하고 확인합니다.
장애 시뮬레이션: 실제 장비에 영향을 주지 않는 화면 시연 기능입니다.
클라우드 배포

위 클라우드 구성도처럼 Render(서버)와 Aiven MySQL(DB)에 올려 인터넷에서 접속할 수 있습니다. 이 저장소에는 배포 설정 파일과 운영 절차를 포함하지 않으며, 로컬 실행을 기준으로 설치 방법을 설명합니다.

주의
.env, 비밀번호, 키 값은 저장소에 올리거나 캡처하지 마세요.
화면의 수치(Mbps, 퍼센트, 장비 수)는 실행 환경마다 다릅니다.
모드 선택 창의 선택값은 브라우저에만 저장됩니다. 다시 보려면 콘솔(F12)에서 openModePicker()를 입력하세요.
연결 코드는 30분 안에 입력해야 합니다.
팀 역할과 담당 범위
역할	담당	담당 파일 및 세부 범위
프로젝트 총괄 및 통합	이지환	• 전체 구조 설계 및 기능 통합
• 대시보드 화면 (public/index.html)
• 설치 가이드와 README (docs/guide.html)
• 공개 저장소 관리 및 클라우드 배포
시스템 백엔드·통합관제 개발	구본학	• 서버 시작과 로그인 인증, JWT 발급 (main.py)
• 회원가입, 관리자 승인, PC 연결 코드 (agent_link.py)
시스템 백엔드·통합관제 개발	장우진	• 장비·구역 관리 API (main.py)
• AI 경보, 조치 승인, 에이전트 API (ai_routes.py)
• 장애 시뮬레이션 (sim_routes.py)
네트워크·데이터 수집	양이수	• PC 상태 측정 후 서버 전송 (collector.py)
• 같은 네트워크 기기 탐색 (scanner.py)
네트워크·데이터 수집	김범수	• 등록된 장비 핑 측정 (pinger.py)
• 의심 프로세스 탐지 (agent.py)
• 차단 에이전트 (agent_ai.py)
데이터베이스·인공지능 분석	김민석	• DB 모델과 연결 설정 (models.py, database.py)
• 전체 테이블 구조 (schema.sql)
데이터베이스·인공지능 분석	최민규	• 기기 식별자 컬럼 마이그레이션 (migrations/001_client_uuid.sql)
데이터베이스·인공지능 분석	김태현	• 응답 시간 기록 마이그레이션 (migrations/002_ping_logs.sql)
• 시연용 가상 장비 생성·삭제 (seed_virtual_devices.py)
데이터베이스·인공지능 분석	박동연	• 이상 탐지 모델, Isolation Forest (src/ai/detector.py)
참고 문헌
C++20으로 배우는 모던한 개발 방식의 성능
데이터베이스 SQL 데이터베이스
Clean VBA: (엑셀 VBA) 기초와 실무
운영체제의 구현과 내부: Operating Internals
지식정보처리의 활용: 이론·구현
소프트웨어 공학: 시스템 개발 방법
SQL & MFC 환경에서 데이터베이스
컴퓨터 네트워크와 관련된 PPT 및 강의 자료
데이터 선정과 평가
컴퓨터 구조와 시스템 프로그래밍
프로그래밍의 이해
데이터 구조와 알고리즘
인공지능 및 데이터 분석 관련 도서
라이선스

학교 졸업 작품으로 공개합니다. 학습 목적으로 자유롭게 참고하셔도 됩니다.
