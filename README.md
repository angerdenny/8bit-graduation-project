# 8bit AI Pulse · AI 기반 네트워크 관제 시스템

네트워크 장비와 PC의 상태(CPU, 메모리, 트래픽, 응답 시간)를 한 화면에서 보고, AI로 이상을 감지하며, 관리자가 승인한 조치(완화·차단)를 실행하는 클라우드 관제 시스템입니다. 관람객이 QR로 폰을 연결해 장애를 직접 일으켜 보고, 관리자가 조치하는 과정을 체험하는 전시용 시연 기능이 들어 있습니다.

- 서버와 대시보드: https://cusor-8bit.onrender.com (실제 환경은 주소 끝에 `?env=real`, 없으면 브라우저가 만든 가상 장비로 움직이는 시뮬레이션 모드)
- 데이터베이스: Aiven MySQL 8.0
- 전시 운영 가이드(설정, 체크리스트, 장애 대응, 설명 스크립트): [docs/EXHIBITION.md](docs/EXHIBITION.md)

> 줄 번호는 2026-11-17 기준으로 `main.py`, `ai_routes.py`, `agent_link.py`, `sim_routes.py`, `index.html`을 다시 확인했습니다. 그 밖의 파일(`collector.py`, `agent.py`, `scanner.py`, `pinger.py`, `models.py`, `database.py`, `schema.sql`, `detector.py`)의 줄 번호는 이번에 다시 확인하지 않았습니다. 코드를 수정하면 줄 번호가 바뀌니 함수 이름으로 검색하세요.

---

## 목차

0. [프로젝트 소개](#0-프로젝트-소개)
1. [팀 역할](#1-팀-역할)
2. [사용 언어와 기술](#2-사용-언어와-기술)
3. [전체 구성](#3-전체-구성)
4. [폴더 구조](#4-폴더-구조)
5. [실행 방법](#5-실행-방법)
6. [화면 사용법](#6-화면-사용법)
7. [상세 문서](#7-상세-문서) (8~15번은 접이식으로 7번 아래에 있습니다)

---

## 0. 프로젝트 소개

### 왜 필요한가
2022년 10월 15일 오후, 경기도 성남시 판교의 SK C&C 데이터센터에서 불이 나 카카오톡, 카카오페이, 카카오T 등이 한꺼번에 멈췄습니다. 카카오는 서버를 이중화해 두었지만 대기 서버를 가동시키는 운영·관리 도구가 같은 데이터센터 안에만 있어서 대기 서버가 제때 동작하지 못했고, 서비스 대부분이 회복되기까지 며칠이 걸렸습니다.

이 사건에서 얻은 교훈은 세 가지입니다.
1. 장애는 한 곳에서 시작해 전체로 번집니다.
2. 사람이 눈으로 확인하기 전에 이상을 먼저 감지해야 합니다.
3. 관리 도구는 감시 대상과 분리되어 있어야 합니다.

이 프로그램은 이상 징후를 AI로 감지해 경보를 만들고, 관리자가 클라우드 안의 한 화면에서 분석과 조치까지 처리하도록 만들었습니다.

참고 기사: [아주경제 2022-10-21](https://www.ajunews.com/view/20221021093734047) · [ZDNet Korea 2022-12-06](https://zdnet.co.kr/view/?no=20221206172822) · [블록미디어](https://www.blockmedia.co.kr/archives/263795)

### 어떤 서버를 쓰는가
| 역할 | 서비스 | 하는 일 |
|---|---|---|
| 웹·API 서버 | Render (클라우드 호스팅) | FastAPI 서버와 대시보드 화면(`public/index.html`) 제공. `main` 브랜치에 push하면 자동 배포 |
| 데이터베이스 | Aiven for MySQL 8.0 (관리형 클라우드 DB) | 사용자, 장비, 측정값, 경보 저장. 서버만 접속 |
| 외부 상태 감시 | UptimeRobot | `/api/health`, `/api/health/db`를 5분마다 확인하고 이상이면 알림 |
| 감시 대상 | 노트북 1대(실측), 가상 장비 9대, 관람객 폰·아이패드 | CPU·메모리·응답 시간 등 |

관리 도구(서버와 DB)는 감시 대상과 분리해서 클라우드에 두었고, 관리자는 인터넷만 되면 어디서나 같은 화면으로 접속합니다.

### 전시 시나리오
1. 관람객이 QR로 접속해 이름과 종류(mobile)로 등록을 요청하고, 관리자가 승인합니다.
2. 승인된 폰 화면 하단의 장애 시뮬레이션(DDoS, 패킷 손실, CPU 고부하, 회선 다운)을 누르면 **자기 기기에만** 장애가 생깁니다.
3. 관리자 화면에 AI 경보와 권장 조치가 뜹니다(DDoS는 차단, 나머지는 완화).
4. 관리자가 🛡️ 위험도 완화(연결 유지) 또는 🚫 연결 차단을 선택하고, 완화 뒤에는 ✅ 해결 완료, 차단 뒤에는 차단 해제를 누릅니다.
5. 폰에는 ① 감지 → ② 분석 → ③ 조치 → ④ 해결 단계가 표시되고, 차단되면 전체 화면 안내가 뜹니다.

> 시연의 **연결 차단은 화면·상태를 바꾸는 논리 차단**입니다. 공유기나 방화벽을 제어하지 않습니다. 실제 프로세스 종료는 `agent.py`의 승인된 차단 흐름(6번)이 따로 처리합니다.

---

## 1. 팀 역할

PPT "역할분담 (개발 조직과 책임 구분)" 기준입니다.

| 구분 | 역할 | 담당자 | 주요 업무 |
|---|---|---|---|
| I | 프로젝트 총괄 및 통합 | 이지환 (팀장) | 전체 진행 관리, 백엔드 API·AI 모델·UI 간 데이터 연동 검증, 소스코드 최종 통합 검수 |
| II | 시스템 백엔드 및 통합관제 개발 | 구본학 | 연동 API와 경보 로직 개발, 실시간 데이터 연동 API 구축, 장애 경보 알림 |
| II | 〃 | 장우진 | 통합관제 화면과 UI 구현, 실시간 관제 대시보드, 상태 맵 시각화, 발표자료(PPT) 총괄 |
| III | 네트워크 및 데이터 수집 | 양이수 | 인프라와 장애 시나리오 설계, 네트워크 구성도(토폴로지) 구축 |
| III | 〃 | 김범수 | 로그 수집 모듈 개발, 장비 상태 로그 자동 수집 스크립트, 포스터 시각화 자료 |
| IV | 데이터 베이스 및 인공지능 분석 | 김민석 | 데이터 구조와 파이프라인 구축, 관제 DB 설계, 데이터 정규화, 수집 파이프라인(ETL) |
| IV | 〃 | 최민규 | 인공지능 이상 탐지 모델 설계, 장애 예측 머신러닝 알고리즘 설계, 학습 데이터셋 가공 |
| IV | 〃 | 김태현 | 모델 최적화, 학습 포스터 제작, 알고리즘 성능 평가, AI 예측 결과 DB 연동 |
| IV | 〃 | 박동연 | 실시간 AI 추론 API와 트래픽 제어 로직 개발, 예측 결과 기반 동적 트래픽 분산 제어, 모델 응답 속도 최적화, 시뮬레이션 검증 |

> 표의 담당자는 PPT 기준입니다. 실제로 누가 어떤 코드를 썼는지는 아래 명령으로 확인할 수 있습니다.
> ```
> git shortlog -sn
> git log --format="%an | %s" -- src/backend/ai_routes.py
> ```

---

## 2. 사용 언어와 기술

| 영역 | 언어 · 기술 | 쓰는 곳 |
|---|---|---|
| 서버 | Python, FastAPI, SQLAlchemy, PyMySQL | `src/backend/main.py`, `ai_routes.py`, `agent_link.py`, `sim_routes.py` |
| 인증 | python-jose (JWT), passlib + bcrypt | `main.py` |
| 에이전트 | Python, psutil, requests | `collector.py`, `agent.py`, `scanner.py`, `pinger.py` |
| AI | scikit-learn (Isolation Forest), numpy, joblib | `src/ai/detector.py` |
| 화면 | HTML, CSS (Tailwind CSS CDN), JavaScript | `public/index.html` |
| 아이콘 | lucide | `public/index.html` |
| 데이터베이스 | MySQL 8.0 (Aiven) | `schema.sql`, `migrations/` |
| 배포 | Render (Build: `pip install -r requirements.txt`) | 서버 설정 |
| 외부 모니터링 | UptimeRobot (무료 플랜) | `/api/health`, `/api/health/db` |

---

## 3. 전체 구성

```
  PC ───────── collector.py ──┐
  노트북 ───── collector.py ──┤
               agent.py ──────┤  (AGENT_API_KEY, 서버 API로만 보고)
               scanner.py ────┤
               pinger.py ─────┤
                              ▼
  관리자 브라우저 ─ 대시보드 ─ FastAPI 서버 (Render) ──── MySQL (Aiven)
  폰·아이패드 ── QR 접속 ────┘          ▲
   (로그인 없이 기기 ID로                │
    응답 시간 보고·장애 버튼)     UptimeRobot ── /api/health
```

- 서버만 DB에 접속합니다. 다른 PC는 DB 주소와 비밀번호를 갖지 않습니다.
- PC는 CPU, 메모리, 트래픽, 패킷 손실을 실제로 측정합니다.
- 스마트폰과 아이패드는 서버까지의 응답 시간과 실패 여부만 측정합니다. CPU와 메모리는 브라우저에서 읽을 수 없습니다.
- 폰·아이패드는 로그인하지 않아도 브라우저가 저장한 기기 ID(`X-Device-Id`)로 식별됩니다. 같은 와이파이라 공인 IP가 같아도 서로 구분됩니다.

---

## 4. 폴더 구조

```
cusor-8bit/
├─ public/
│  └─ index.html          대시보드 화면 (HTML, CSS, JavaScript 한 파일)
├─ src/
│  ├─ backend/
│  │  ├─ main.py          서버 시작, 로그인, 장비·구역·연결·이벤트 API, 상태 확인 (Python)
│  │  ├─ ai_routes.py     AI 경보, 차단 승인, 에이전트 API, 기기 등록, 백업·복구 (Python)
│  │  ├─ agent_link.py    회원가입, 관리자 승인, PC 연결 코드, 탈퇴, 측정값 API (Python)
│  │  ├─ sim_routes.py    시연 장애 시뮬레이션, 완화·차단·해결, 가상 장비 데이터 (Python)
│  │  ├─ models.py        ORM 모델 (Python, SQLAlchemy)
│  │  ├─ database.py      DB 연결 설정 (Python, 서버 외 프로그램이 사용)
│  │  ├─ collector.py     PC 상태 측정 후 서버 전송 (Python)
│  │  ├─ agent.py         의심 프로세스 탐지, 승인된 차단 실행 (Python)
│  │  ├─ scanner.py       같은 네트워크의 기기 탐색 (Python, Windows 명령 사용)
│  │  ├─ pinger.py        등록된 기기 핑 측정 (Python, Windows 명령 사용)
│  │  └─ seed_virtual_devices.py  전시용 가상 장비 생성·삭제 (Python)
│  └─ ai/
│     └─ detector.py      이상 탐지 모델 (Python, scikit-learn)
├─ migrations/
│  ├─ 001_client_uuid.sql        기기 식별자 컬럼 추가 (SQL)
│  ├─ 002_ping_logs.sql          응답 시간 기록 테이블 (SQL)
│  └─ 003_alerts_device_id.sql   경보에 장비 번호 컬럼 추가 (SQL, 서버 시작 때 자동 적용되므로 선택)
├─ docs/
│  └─ EXHIBITION.md       전시 운영 가이드 (설정, 체크리스트, 장애 대응, 설명 스크립트)
├─ schema.sql             전체 테이블 생성 (SQL)
├─ requirements.txt       Python 패키지 목록
├─ .env.example           환경변수 이름 목록 (값 없음)
└─ .gitignore             .env, backup/, agent_id.txt 등 제외
```

---

## 5. 실행 방법

### 5-1. 서버 (Render)
- `main` 브랜치에 push하면 자동 배포됩니다. 전시 기간에는 Settings의 Auto-Deploy를 끄고 수동 배포를 권장합니다.
- Build Command: `pip install -r requirements.txt`
- Start Command: `PYTHONPATH=. uvicorn src.backend.main:app --host 0.0.0.0 --port $PORT`
  - 이 명령은 **저장소 루트**에서 실행되어 `src.backend`를 패키지로 읽습니다. 그래서 서버 파일끼리는 상대 import(`from .ai_routes import ...`)를 씁니다. 규칙은 아래 'Python import 규칙'을 따르세요.
- 상태 확인: `https://cusor-8bit.onrender.com/api/health` (서버), `/api/health/db` (DB까지 확인, 응답이 없으면 503)
- 인스턴스는 **1개**, 워커도 **1개**로 실행합니다. 승인 대기, 시연 상태 등이 서버 메모리에 있어서 여러 개로 늘리면 상태가 꼬입니다.
- 필요한 환경변수는 아래 9번을 참고하세요.

### 5-2. 노트북 (로컬 측정과 감시)
```powershell
cd "저장소경로\src\backend"
python collector.py     # 이 PC의 CPU, 메모리 측정 (10초마다 전체 장비 현황 표 출력)
python agent.py         # 의심 프로세스 감시 (관리자 PowerShell 권장)
```
서버를 내 PC에서 직접 띄울 때는 두 가지 방법이 있습니다. 배포 방식과 같은 방법을 쓰면 Render에서도 똑같이 뜹니다.
```powershell
# 방법 1: src\backend에서 실행 (가장 흔한 개발 방식)
cd "저장소경로\src\backend"
uvicorn main:app

# 방법 2: Render와 같은 방식 (저장소 루트에서 실행)
cd "저장소경로"
$env:PYTHONPATH="."
uvicorn src.backend.main:app
```
두 방법 모두 `Uvicorn running on http://127.0.0.1:8000`이 나오면 정상입니다.

`.env`는 `src/backend/` 폴더에 두고, 값은 Render의 Environment 설정과 맞춥니다. 값을 저장소나 채팅에 올리지 마세요.
관리자 노트북은 서버의 `ADMIN_AGENT_IDS`에 PC ID를 등록하면 연결 코드 없이 자동으로 관리자 소유로 연결됩니다.

### 5-3. 다른 PC 연결 (일반 사용자)
1. 로그인 화면에서 회원가입합니다. **구역 접근은 관리자가 승인해야 열립니다.** 승인 전에는 로그인해도 구역이 없습니다.
2. 연결할 PC에 패키지를 설치합니다.
   ```
   pip install psutil python-dotenv requests
   ```
3. PC 폴더에 `collector.py`와 `.env`를 둡니다. `.env`는 두 줄입니다.
   ```
   BACKEND_URL=https://cusor-8bit.onrender.com
   AGENT_API_KEY=(관리자에게 받은 값)
   ```
4. `python collector.py`를 실행하면 화면에 6자리 코드가 표시됩니다.
5. **관리자가 대시보드의 승인 대기 목록에서 그 PC를 해당 사용자에게 승인**합니다 (`/api/access/approve-pc`).
6. 승인된 사용자가 웹 로그인 → 사이드바 "내 PC 연결"에서 코드를 입력합니다. 승인되지 않은 사용자는 코드를 입력할 수 없습니다.
7. 연결 후 콘솔에 측정값이 5초마다 표시됩니다. `agent_id.txt`는 PC 고유 ID이므로 삭제하지 마세요.

### 5-4. 관람객 폰·아이패드 연결 (QR, 로그인 없이)
1. `https://cusor-8bit.onrender.com/?env=real`을 QR로 만들어 둡니다.
2. 관람객이 접속하면 등록되지 않은 기기에는 "이 기기는 등록되어 있지 않아요" 창이 뜹니다. 이름을 입력하고 종류를 `mobile`로 두고 등록을 요청합니다.
3. 관리자가 대시보드의 등록 요청 창에서 구역을 고르고 승인(또는 거절)합니다. 승인되면 기기 화면에 장애 시뮬레이션 패널이 나타납니다.
4. **폰·아이패드는 로그인하지 않는 것이 기본입니다.** 일반 계정으로 로그인하면 "기기 사용자 모드"로 전환되어 `내 기기` 화면이 열립니다(6번).

### 5-5. 가상 장비 (전시용)
```powershell
python src/backend/seed_virtual_devices.py --dry        # 미리보기
python src/backend/seed_virtual_devices.py              # 팀원 9명에게 'OOO PC (가상)'을 1대씩 만들고 연결
python src/backend/seed_virtual_devices.py --no-links   # 연결선 없이 장비만
python src/backend/seed_virtual_devices.py --remove     # 전시가 끝나면 삭제
```
가상 장비의 측정값은 대시보드가 열려 있을 때만, 대시보드가 조회할 때마다(장비당 최소 4초 간격) 새로 만들어지고 DB에는 한 번에 저장됩니다. 장비마다 평소 수치와 물결 주기가 다르고 가끔 작은 급증이 있으며, AI 기준선에서 크게 벗어나지 않도록 상·하한(CPU 6~48%, 메모리 52~78%, 트래픽 0.02~0.9Mbps)을 둡니다. 30분이 지난 값은 자동 삭제됩니다.

---

## 6. 화면 사용법

| 메뉴 | 내용 |
|---|---|
| 대시보드 | 실시간 트래픽, 기기 현황, AI 위험 점수, 최근 알림 (기기 사용자에게는 `내 기기` 화면) |
| 네트워크 토폴로지 | 장비 연결 구조. 장비를 누르면 진단 창이 열림 |
| VLAN 구역 | 구역별 장비만 보기 |
| 트래픽 · AI 분석 | 확대 차트, 장비별 부하 |
| 보안 로그 | 경보 기록, 엔드포인트 이벤트, 필터 |
| 기기 관리 | 기기 추가, 소유자 지정, 백업·복구 |
| 내 PC 연결 | 연결 코드 입력, 내 PC 목록, 회원 탈퇴 |
| AI 가이드 | 사용법 질의응답, 팀 역할 |

### 권한
- **관리자**: 모든 장비·구역·경보 조회, 기기와 사용자 승인, 완화·차단 조치, 백업·복구
- **일반 사용자(로그인)**: 관리자가 구역 접근을 승인한 뒤 사용할 수 있습니다. **본인이 소유한 장비와 그 장비의 경보만** 보이고, 사용자 목록에는 본인만 나옵니다. 엔드포인트 보안 이벤트는 관리자 전용이라 빈 목록을 받습니다.
- **로그인 없는 기기(QR)**: 기기 ID로 식별되는 **본인 기기**의 상태 확인, 장애 시뮬레이션, 연결 끊기, 재연결 요청만 할 수 있습니다.

### 기기 사용자 모드 (아이패드·폰)
일반 계정으로 로그인했고 이 브라우저가 등록된 기기일 때 켜집니다.
- 대시보드 본 화면이 **`내 기기`** 화면으로 바뀌어 연결 상태(원활·느림·불안정·끊김), 응답 시간, 연결 실패율, 흔들림, 응답 시간 차트, 다운로드 속도 측정, 장애 시뮬레이션 버튼을 보여 줍니다.
- 메뉴는 `내 기기`와 `AI 가이드`만 남고, 토폴로지·분석·보안 로그·기기 관리·내 PC 연결은 숨겨집니다.
- 로그인하지 않은 화면과 다른 메뉴에서는 하단에 접었다 펼 수 있는 한 줄 패널이 나오고, 아이디·비밀번호 같은 입력칸에 글을 쓰는 동안에는 자동으로 숨습니다.

### 시연 장애 흐름
1. 기기에서 장애 버튼(DDoS, 패킷 손실, CPU 고부하, 회선 다운)을 누릅니다. 같은 기기는 8초에 한 번, 전체 동시 30개까지 가능하고 10분 뒤 자동 종료됩니다.
2. 서버가 AI 경보를 만들고 관리자 화면에 팝업과 권장 조치를 보여 줍니다. 권장 규칙은 **DDoS는 차단, 나머지는 완화**입니다.
3. 관리자가 🛡️ 위험도 완화(연결 유지) 또는 🚫 연결 차단을 선택합니다. 완화 뒤에는 ✅ 해결 완료, 차단 뒤에는 차단 해제를 누릅니다.
4. 기기에는 ① 감지 → ② 분석 → ③ 조치 → ④ 해결 단계가 표시됩니다. 장애 중에는 🔌 직접 연결 끊기, 차단 중에는 🔄 재연결 요청을 누를 수 있고, 차단 해제는 관리자만 합니다.
5. 차단 목록은 DB(`device_blocks`)에 남고, 진행 중인 장애 상태는 서버 메모리에 있습니다.

### 경보·승인 팝업의 "나중에"
AI 이상 감지, 기기 등록 요청, 가입 승인, PC 연결 승인 팝업에서 **나중에**를 누르면 "어떻게 하실 예정인가요?"를 되묻습니다.
- 🚨 지금 처리할게요: 원래 팝업을 바로 다시 엽니다.
- ⏱ 1분 / 5분 뒤에 다시 알려 주세요: 정한 시간이 지나면 같은 팝업이 다시 뜹니다. 그동안 지도에는 "조치 대기"가 그대로 남습니다.
- 👀 계속 지켜볼게요 (AI 이상 감지 경보만): 지도에 주황색 "지켜보는 중"으로 표시하고 팝업은 더 이상 띄우지 않습니다. 장비를 눌러 진단 창의 **경보 확인하고 처리하기**로 언제든 다시 처리할 수 있습니다. 서버의 경보는 열린 상태 그대로이고, 오탐 처리나 조치로 닫으면 표시도 사라집니다.

### 서버 끊김과 세션 안내
- 서버 요청이 계속 실패하면 화면 위에 "서버에 연결하지 못하고 있어요" 배너가 뜨고, 돌아오면 초록 배너와 함께 60초 동안 새로 생기는 자동 경보(오프라인·AI 이상 감지)를 보류합니다.
- 로그인 토큰이 만료되면 "로그인 시간이 지나 세션이 만료되었어요" 안내와 함께 로그인 1단계로 돌아가고, 만료 3분 전에 미리 알려 줍니다.

### 차단 흐름 (의심 프로세스, 에이전트)
1. `agent.py`가 감시 목록과 이름이 정확히 같은 프로세스를 찾으면 `detected`로 기록합니다. 이때는 종료하지 않습니다.
2. AI가 이상을 감지하면 경보가 만들어지고, 의심 프로세스 정보가 함께 연결됩니다. 같은 장비의 최신 측정값이 **연속으로 이상일 때만** 경보를 만듭니다(`AI_CONFIRM_COUNT`, 기본 2회).
3. 관리자가 대시보드에서 차단을 승인합니다.
4. `agent.py`가 명령을 받아 PID, 이름, 생성 시각이 모두 맞을 때만 종료하고 결과를 보고합니다.

---

## 7. 상세 문서

<details>
<summary><b>7-1. 프로젝트 총괄 및 통합 — 이지환 (팀장)</b></summary>

**담당 업무 (PPT 기준)**
- 전체 프로젝트 진행 상황 관리, 팀원 개발 현황 점검
- 백엔드 API, AI 모델, UI 간 데이터 연동 검증
- 소스코드 최종 통합 검수

**구현 범위 (코드)**: 로그인, 권한 판단, 회원가입, PC 연결, 회원 탈퇴

| 파일 | 언어 | 위치 | 설명 |
|---|---|---|---|
| `src/backend/main.py` | Python | L122–L123 | 로그인 실패 잠금 설정 (기본 10회·60분, 환경변수 `LOGIN_MAX_ATTEMPTS`·`LOGIN_BLOCK_MINUTES`로 변경) |
| `src/backend/main.py` | Python | L190 | `get_current_user` 토큰 검사 |
| `src/backend/main.py` | Python | L217 | `require_admin` 관리자 검사 |
| `src/backend/main.py` | Python | L227–L268 | `/api/auth/login` 로그인 |
| `src/backend/main.py` | Python | L603–L604 | 일반 사용자 장비 목록을 본인 PC로 거르는 부분 |
| `src/backend/agent_link.py` | Python | L110 | `/api/auth/register` 회원가입 (구역 권한은 관리자 승인 후 부여) |
| `src/backend/agent_link.py` | Python | L179 | `/api/link/claim` 연결 코드 확인 (관리자가 승인한 사용자만) |
| `src/backend/agent_link.py` | Python | L297–L311 | `/api/auth/me` (DELETE) 회원 탈퇴 |
| `src/backend/ai_routes.py` | Python | L183 | `visible_device_ids` 장비 조회 범위 계산 |

**핵심 코드**

장비 목록 권한 (`main.py`, L551–L552):
```python
if current_user.get("role") != "admin":
    device_rows = [r for r in device_rows if r.owner_id == current_user["user_id"]]
```

회원 탈퇴 (`agent_link.py`):
```python
if current_user.get("role") == "admin":
    raise HTTPException(status_code=403, detail="관리자 계정은 탈퇴할 수 없습니다")
...
if not pwd_context.verify(body.password, row.password_hash):
    raise HTTPException(status_code=400, detail="비밀번호가 올바르지 않습니다")
db.execute(text("DELETE FROM users WHERE id=:u"), {"u": uid})
```

</details>

<details>
<summary><b>7-2. 시스템 백엔드 및 통합관제 개발 — 장우진</b></summary>

**담당 업무 (PPT 기준)**
- 통합관제 화면과 UI 구현
- 실시간 관제 대시보드 화면 구현
- 상태 맵 시각화
- 발표자료(PPT) 총괄 제작 (코드 아님)

**구현 범위 (코드)**: 대시보드 카드, 알림 표시, 서버 호출 공통 함수

| 파일 | 언어 | 위치 | 설명 |
|---|---|---|---|
| `public/index.html` | HTML | L2635 | 대시보드 섹션 시작 (기기 사용자에게는 `mydev-overview` 화면으로 바뀜) |
| `public/index.html` | HTML | L2705 | 실시간 수신 트래픽 카드 (`traffic-card`) |
| `public/index.html` | HTML | L2797 | 최근 알림 칸 (`alert-mini`) |
| `public/index.html` | JavaScript | L3629 | `apiFetch` 토큰 첨부, 401이면 안내 후 로그인 화면으로 |
| `public/index.html` | JavaScript | L5890 | `renderAlerts` 알림 목록 그리기 |
| `public/index.html` | JavaScript | L4269 | `switchView` 화면 전환 |

**핵심 코드**

서버 호출 공통 함수 (`index.html`, `apiFetch`):
```javascript
async function apiFetch(url, options = {}) {
    const token = sessionStorage.getItem('token');
    const headers = { ...(options.headers || {}) };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const res = await fetch(url, { ...options, headers });
    if (res.status === 401) { logout(); throw new Error('세션이 만료되었습니다'); }
    return res;
}
```

최근 알림 칸 (`renderAlerts`):
```javascript
const mini = document.getElementById('alert-mini');
if (mini) mini.innerHTML = alertList.length ? alertList.slice(0, 5).map(alertHtml).join('') : /* 빈 안내 */;
```

</details>

<details>
<summary><b>7-3. 네트워크 및 데이터 수집 — 양이수</b></summary>

**담당 업무 (PPT 기준)**
- 인프라 및 장애 시나리오 설계
- 네트워크 구성도(토폴로지) 구축

**구현 범위 (코드)**: 토폴로지 노드 배치, 연결선, 구역 영역, 확대와 이동

| 파일 | 언어 | 위치 | 설명 |
|---|---|---|---|
| `public/index.html` | JavaScript | L4049 | `SIM_TYPES` 장애 시나리오 정의 (DDoS, 패킷 손실 등) |
| `public/index.html` | HTML | L2766 | 관리자용 장애 시뮬레이션 패널 |

| 파일 | 언어 | 위치 | 설명 |
|---|---|---|---|
| `public/index.html` | HTML | L2813 | 토폴로지 섹션 시작 |
| `public/index.html` | JavaScript | L3994 | `EDGES` 기본 연결 목록 |
| `public/index.html` | JavaScript | L3996 | `edgeId` 연결선 ID 만들기 |
| `public/index.html` | JavaScript | L4580 | `buildNodeUI` 노드 화면 만들기 |
| `public/index.html` | JavaScript | L4652 | `onTopoPointerDown` 드래그 시작 |
| `public/index.html` | JavaScript | L4736 | `computeTopoGraph` 그래프 계산 |
| `public/index.html` | JavaScript | L4789 | `layoutTiers` 계층 배치 |
| `public/index.html` | JavaScript | L4382 | `renderVlanView` 구역 화면 그리기 |
| `src/backend/main.py` | Python | L796 | `/api/links` 연결선 추가 |
| `src/backend/main.py` | Python | L839 | `/api/links` 연결선 삭제 |

**핵심 코드**

연결선 ID (`index.html`, `edgeId`):
```javascript
function edgeId(a, b) { return `ln-${a}__${b}`; }
```

</details>

<details>
<summary><b>7-4. 네트워크 및 데이터 수집 — 김범수</b></summary>

**담당 업무 (PPT 기준)**
- 로그 수집 모듈 개발
- 장비 상태 로그 자동 수집 스크립트 개발
- 포스터 시각화 자료 제작 (코드 아님)

**구현 범위 (코드)**: PC 측정과 전송, 기기 탐색, 프로세스 감시, 기기 핑

| 파일 | 언어 | 위치 | 설명 |
|---|---|---|---|
| `src/backend/collector.py` | Python | L37 | `load_agent_id` PC 고유 ID 만들기·읽기 |
| `src/backend/collector.py` | Python | L57 | `measure_packet_loss` 패킷 손실 측정 |
| `src/backend/collector.py` | Python | L70 | `wait_for_link` 연결 코드 표시와 연결 대기 |
| `src/backend/collector.py` | Python | L95 | `main` 측정 루프 |
| `src/backend/collector.py` | Python | L110 | 수신 트래픽 계산 (Mbps) |
| `agent.py` | Python | L32 | `SUSPICIOUS_NAMES` 감시 목록 |
| `agent.py` | Python | L35 | `PROTECTED_NAMES` 종료 제외 목록 |
| `agent.py` | Python | L88 | `scan_suspicious` 의심 프로세스 찾기 |
| `agent.py` | Python | L103 | `report_suspicious` 탐지 기록과 의심 정보 전송 |
| `agent.py` | Python | L126 | `try_kill` 승인된 명령 실행 (PID, 이름, 생성 시각 확인) |
| `agent.py` | Python | L164 | `poll_commands` 차단 명령 가져오기 |
| `scanner.py` | Python | L26 | `ARP_RE` ARP 표 해석 정규식 |
| `scanner.py` | Python | L49 | `arp_hosts` 같은 대역의 기기 찾기 |
| `scanner.py` | Python | L75 | `scan_once` 핑 후 ARP 표 읽기 |
| `pinger.py` | Python | L17 | `ping` 핑 한 번 보내기 |
| `pinger.py` | Python | L35 | `main` 등록된 기기 핑 루프 |

**핵심 코드**

수신 트래픽 계산 (`collector.py`, L110):
```python
traffic_in = round((net.bytes_recv - last.bytes_recv) * 8 / elapsed / 1_000_000, 3)
```

ARP 표 해석 (`scanner.py`, L26):
```python
ARP_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})")
```

</details>

<details>
<summary><b>7-5. 시스템 백엔드 및 통합관제 개발 — 구본학</b></summary>

**담당 업무 (PPT 기준)**
- 연동 API와 경보 로직 개발
- 실시간 데이터 연동 API 구축
- 장애 경보 알림

**구현 범위 (코드)**: AI 경보 생성, 차단 승인과 명령 전달, 에이전트 API, 기기 등록 요청

| 파일 | 언어 | 위치 | 설명 |
|---|---|---|---|
| `src/backend/ai_routes.py` | Python | L37 | `SUSPECT_TTL` 오래된 의심 보고 무시 기준 (60초) |
| `src/backend/ai_routes.py` | Python | L173 | `add_alert` 경보 기록 추가 (`device_id`로 어느 장비의 경보인지 함께 저장) |
| `src/backend/ai_routes.py` | Python | L227 | `score_rows` 측정값에 위험 점수를 붙이고, 최신 측정값이 연속으로 이상일 때만 경보 생성 |
| `src/backend/ai_routes.py` | Python | L279 | `build_ai_router` 라우터 묶음 생성 |
| `src/backend/ai_routes.py` | Python | L282 | `agent_auth` 에이전트 키 검사 |
| `src/backend/ai_routes.py` | Python | L307 | `/api/security/block` 차단 승인 |
| `src/backend/ai_routes.py` | Python | L347–L375 | 에이전트 `hello`, `suspect`, `commands`, 결과 보고 |
| `src/backend/ai_routes.py` | Python | L424 | `/api/ai/register-request` 기기 등록 요청 |
| `src/backend/ai_routes.py` | Python | L462 | `/api/ai/heartbeat` 응답 시간 기록 (등록된 기기만) |
| `src/backend/main.py` | Python | L883 | `/api/alerts` 알림 목록 (관리자는 전체, 일반 사용자는 본인 장비 경보만) |
| `src/backend/main.py` | Python | L902–L951 | 엔드포인트 이벤트 조회(관리자 전용)·기록 |

**핵심 코드**

의심 보고 유효 시간 (`ai_routes.py`, L37):
```python
SUSPECT_TTL = 60  # 초. 이보다 오래된 의심 프로세스 보고는 무시
```

차단 명령 전달 (`ai_routes.py`, L295):
```python
@r.get("/api/agent/commands", dependencies=[Depends(agent_auth)])
def poll_commands(device_id: int):
```

</details>

<details>
<summary><b>7-6. 데이터 베이스 및 인공지능 분석 — 김민석</b></summary>

**담당 업무 (PPT 기준)**
- 데이터 구조 및 파이프라인 구축
- 관제 DB 설계
- 데이터 정규화와 수집 파이프라인(ETL) 구축

**구현 범위 (코드)**: 테이블 설계, 마이그레이션, ORM 모델, DB 연결, 백업·복구

| 파일 | 언어 | 위치 | 설명 |
|---|---|---|---|
| `schema.sql` | SQL | L9 | 기존 테이블 삭제 (운영 DB에 실행하면 데이터가 지워짐) |
| `schema.sql` | SQL | L25 | `users` 테이블 |
| `schema.sql` | SQL | L57 | `devices` 테이블 (좌표 제약 포함) |
| `schema.sql` | SQL | L108 | `telemetry` 테이블 (측정값) |
| `schema.sql` | SQL | L132 | `alerts` 테이블 (알림) |
| `schema.sql` | SQL | L196 | `user_vlans` 테이블 (구역 권한) |
| `schema.sql` | SQL | L212 | `endpoint_events` 테이블 (보안 이벤트) |
| `schema.sql` | SQL | L225 | `v_latest_telemetry` 뷰 (장비별 최신 측정값) |
| `schema.sql` | SQL | L256 | `ai_incidents` 테이블 (AI 경보) |
| `schema.sql` | SQL | L271 | `ping_logs` 테이블 (응답 시간) |
| `migrations/001_client_uuid.sql` | SQL | 전체 | `devices.client_uuid` 추가, 인덱스 변경 |
| `migrations/002_ping_logs.sql` | SQL | 전체 | `ping_logs` 생성 (여러 번 실행해도 안전) |
| `src/backend/models.py` | Python | L13–L82 | ORM 모델 (User, Vlan, Device, Telemetry, Alert 등) |
| `src/backend/database.py` | Python | L17 | `get_db` 요청마다 DB 세션 열고 닫기 |
| `src/backend/ai_routes.py` | Python | L483 | `/api/admin/backup` 백업 내보내기 |
| `src/backend/ai_routes.py` | Python | L504 | `/api/admin/restore` 백업 복구 |

**핵심 코드**

사용자 테이블 (`schema.sql`, L25):
```sql
CREATE TABLE users (
    id            INT          NOT NULL AUTO_INCREMENT,
    username      VARCHAR(50)  NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role          VARCHAR(10)  NOT NULL DEFAULT 'user',
```

DB 세션 (`database.py`, L17):
```python
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

</details>

<details>
<summary><b>7-7. 데이터 베이스 및 인공지능 분석 — 최민규, 김태현</b></summary>

**담당 업무 (PPT 기준)**
- 최민규: 인공지능 이상 탐지 모델 설계, 장애 예측 머신러닝 알고리즘 설계, 학습 데이터셋 가공
- 김태현: 모델 최적화, 알고리즘 성능 평가, AI 예측 결과 DB 연동, 학습 포스터 제작 (코드 아님)

**구현 범위 (코드)**: 이상 탐지 모델 학습, 위험 점수 계산, 오탐 재학습

| 파일 | 언어 | 위치 | 설명 |
|---|---|---|---|
| `src/backend/ai_routes.py` | Python | L268 | `ai_incidents` 테이블에 AI 예측 결과 저장 (AI 예측 결과 DB 연동) |

| 파일 | 언어 | 위치 | 설명 |
|---|---|---|---|
| `src/ai/detector.py` | Python | L22 | `NetworkAnomalyDetector` 클래스 |
| `src/ai/detector.py` | Python | L40 | `train_baseline` 정상 기준선 학습 |
| `src/ai/detector.py` | Python | L58 | `predict_risk` 위험 점수 계산 |
| `src/ai/detector.py` | Python | L70 | 점수 공식 (0–100) |
| `src/ai/detector.py` | Python | L77 | `add_feedback` 오탐 샘플로 재학습 |
| `src/backend/ai_routes.py` | Python | L30 | `train_query` 학습 데이터 조회 (`AI_TRAIN_DEVICE_ID` 사용) |
| `src/backend/ai_routes.py` | Python | L227 | `score_rows` 측정값마다 위험 점수 붙이기 (연속 확인 후 경보) |
| `src/backend/ai_routes.py` | Python | L298 | `/api/ai/train` 재학습 (관리자) |
| `src/backend/ai_routes.py` | Python | L328 | `/api/ai/feedback` 오탐 피드백 (관리자) |

**핵심 코드**

위험 점수 공식 (`detector.py`, L70):
```python
risk = 100.0 / (1.0 + np.exp(np.clip(SENSITIVITY * d, -50, 50)))
```
- `d`는 모델의 판정 값입니다. 양수는 정상, 음수는 이상입니다.
- 점수가 `ANOMALY_THRESHOLD`(60) 이상이면 이상으로 봅니다.

**알려진 제약**: 지연(ping) 특성은 현재 측정값에 없어서 항상 0입니다. 실제 점수는 CPU, 메모리, 트래픽 중심입니다.

</details>

<details>
<summary><b>7-8. 데이터 베이스 및 인공지능 분석 — 박동연</b></summary>

**담당 업무 (PPT 기준)**
- 실시간 AI 추론 API와 트래픽 제어 로직 개발
- 예측 결과 기반 동적 트래픽 분산 제어
- 모델 응답 속도 최적화 및 시뮬레이션 검증

**구현 범위 (코드)**: 추론 호출과 트래픽 관련 처리 (담당 파일 확인 필요)

| 파일 | 언어 | 위치 | 설명 |
|---|---|---|---|
| `src/backend/ai_routes.py` | Python | L240 | `predict_risk` 추론 호출 (위험 점수 계산) |
| `src/backend/ai_routes.py` | Python | L334–L341 | 오탐 피드백 전후 위험 점수 비교 |
| `src/backend/collector.py` | Python | L110 | 수신 트래픽 계산 (Mbps) |

</details>

<details>
<summary><b>7-9. 시연 기능과 운영 보강 (장애 시뮬레이션, 기기 화면, 서버 안정화)</b></summary>

**담당**: 팀 확인 후 기입 (구현 기여는 `git log --format="%an | %s" -- src/backend/sim_routes.py`로 확인)

**구현 범위 (코드)**: 시연 장애 시나리오, 완화·차단·해결 흐름, 가상 장비 데이터, 기기 사용자 화면, 서버 끊김·세션 만료 안내, 계정별 경보 필터, AI 경보 연속 확인

| 파일 | 언어 | 위치 | 설명 |
|---|---|---|---|
| `src/backend/sim_routes.py` | Python | L56 | `PROFILES` 장애 4종(DDoS, 패킷 손실, CPU 고부하, 회선 다운)의 수치와 권장 조치 |
| `src/backend/sim_routes.py` | Python | L308 | `_start_sim` 시나리오 시작, 경보·팝업 생성 |
| `src/backend/sim_routes.py` | Python | L239 | `apply_active_sims` 진행 중 장애와 가상 장비 측정값 생성 |
| `src/backend/sim_routes.py` | Python | L346 | `/api/sim/device-inject` 기기가 자기 장비에만 장애 시작 |
| `src/backend/sim_routes.py` | Python | L450 | `/api/sim/mitigate` 위험도 완화 |
| `src/backend/sim_routes.py` | Python | L470 | `/api/sim/block` 연결 차단 (DB `device_blocks`에 기록) |
| `src/backend/sim_routes.py` | Python | L563 | `/api/sim/my-status` 기기 화면용 상태 |
| `src/backend/ai_routes.py` | Python | L54 | `AI_CONFIRM_COUNT` 경보 확인 횟수 설정 |
| `src/backend/ai_routes.py` | Python | L143 | `ensure_alert_scope` 경보 테이블에 `device_id` 컬럼 준비 |
| `src/backend/main.py` | Python | L44 | `int_env` 숫자 환경변수 읽기 (오타여도 서버가 죽지 않음) |
| `src/backend/main.py` | Python | L65 | `RealClientIP` 프록시 뒤에서 실제 접속 IP 사용 |
| `src/backend/main.py` | Python | L963 | `/api/health/db` DB까지 확인하는 상태 점검 |
| `public/index.html` | JavaScript | L3507 | `noteServer` 서버 끊김 감시와 복구 유예 |
| `public/index.html` | JavaScript | L3898 | `expireSession` 토큰 만료 안내 후 1단계로 |
| `public/index.html` | JavaScript | L7688 | `connQuality` 연결 상태(원활·느림·불안정·끊김) 계산 |
| `public/index.html` | JavaScript | L7744 | `renderDevicePanel` 하단 접이식 패널 |
| `public/index.html` | JavaScript | L7807 | `applyDeviceMode` 기기 사용자 모드 전환, 메뉴 정리 |
| `public/index.html` | JavaScript | L7844 | `renderMyDeviceOverview` `내 기기` 화면 그리기 |
| `public/index.html` | JavaScript | L7715 | `runSpeedTest` 다운로드 속도 측정 |
| `public/index.html` | JavaScript | L7566 | `checkReconnectRequests` 재연결 요청 팝업 (관리자) |
| `public/index.html` | JavaScript | L6863 | `isAutoAlert` 복구 직후 숨길 자동 경보 분류 |
| `public/index.html` | JavaScript | L7097 | `laterAsk` "나중에"를 누르면 어떻게 할지 되묻기 (1분·5분 뒤 다시 알림, 지켜보기) |
| `public/index.html` | JavaScript | L7145 | `pollAiIncidents` AI 경보 팝업, 미룸·지켜보기 처리 |
| `public/index.html` | JavaScript | L6077 | `trafficMax` 실제 환경에서 트래픽 차트 세로축을 값에 맞춰 자동 조절 |
| `src/backend/sim_routes.py` | Python | L153 | `_virtual_sample` 가상 장비 측정값 (물결 + 가끔 급증, 한도 안에서) |

**핵심 코드**

AI 경보는 최신 측정값이 연속으로 이상일 때만 만듭니다 (`ai_routes.py`, `score_rows`):
```python
need = AI_CONFIRM_COUNT
if len(results) < need or not all(x["is_anomaly"] for x in results[:need]):
    continue  # 최신 측정값이 연속으로 이상일 때만 (한 번 튀는 값은 무시)
```

경보는 계정별로 거릅니다 (`main.py`, `get_alerts`):
```python
if current_user.get("role") == "admin":
    rows = db.execute(text("SELECT * FROM alerts ORDER BY id DESC LIMIT 100")).fetchall()
else:
    ids = visible_device_ids(db, current_user)
    if not ids or not ensure_alert_scope(db):
        return {"alerts": []}   # 소유한 장비가 없거나 필터가 준비되지 않으면 아무것도 보여 주지 않음
    rows = db.execute(text("SELECT * FROM alerts WHERE device_id IN :ids ORDER BY id DESC LIMIT 100")
                      .bindparams(bindparam("ids", expanding=True)), {"ids": list(ids)}).fetchall()
```

</details>

<details>
<summary><b>8. 전체 API 목록</b></summary>

인증이 필요한 API는 `Authorization: Bearer <토큰>` 헤더를 씁니다. 에이전트 API는 `X-API-Key` 헤더를 씁니다.

**사용자 · 인증**

| 메서드 | 경로 | 파일 : 줄 | 설명 |
|---|---|---|---|
| POST | `/api/auth/login` | main.py : 227 | 로그인 (계정별 실패 횟수 초과 시 잠금, 기본 10회·60분) |
| GET | `/api/auth/me` | main.py : 270 | 내 정보 |
| DELETE | `/api/auth/me` | agent_link.py : 297 | 회원 탈퇴 |
| POST | `/api/auth/register` | agent_link.py : 110 | 회원가입 |
| POST | `/api/auth/validate-vlan` | main.py : 300 | 구역 코드 확인 후 토큰 재발급 |
| GET | `/api/auth/my-zones` | main.py : 347 | 들어갈 수 있는 구역 목록 |
| GET | `/api/users` | main.py : 622 | 사용자 목록 (관리자는 전체, 일반 사용자는 본인만) |

**장비 · 구역 · 연결**

| 메서드 | 경로 | 파일 : 줄 | 설명 |
|---|---|---|---|
| GET | `/api/devices` | main.py : 564 | 장비, 연결선, 구역 목록 |
| POST | `/api/devices` | main.py : 684 | 장비 추가 (관리자) |
| PUT | `/api/devices/{id}` | main.py : 717 | 장비 수정 (관리자) |
| DELETE | `/api/devices/{id}` | main.py : 768 | 장비 삭제 (관리자) |
| POST | `/api/links` | main.py : 796 | 연결선 추가 |
| DELETE | `/api/links` | main.py : 839 | 연결선 삭제 |
| GET | `/api/vlans` | main.py : 641 | 구역 목록 |
| POST | `/api/vlans` | main.py : 647 | 구역 추가 (관리자) |
| PUT | `/api/vlans/{id}` | main.py : 661 | 구역 수정 (관리자) |
| DELETE | `/api/vlans/{id}` | main.py : 674 | 구역 삭제 (관리자) |
| POST | `/api/link/claim` | agent_link.py : 179 | 연결 코드로 PC 연결 (관리자가 승인한 사용자만) |

**측정 · 경보 · 이벤트**

| 메서드 | 경로 | 파일 : 줄 | 설명 |
|---|---|---|---|
| GET | `/api/telemetry/latest` | main.py : 863 | 최근 측정값과 위험 점수 |
| GET | `/api/alerts` | main.py : 883 | 알림 목록 (관리자는 전체, 일반 사용자는 본인 장비 경보만) |
| GET | `/api/ai/incidents` | ai_routes.py : 287 | AI 경보 목록 |
| POST | `/api/ai/train` | ai_routes.py : 298 | 기준선 재학습 (관리자) |
| POST | `/api/security/block` | ai_routes.py : 307 | 차단 승인 (관리자) |
| POST | `/api/ai/feedback` | ai_routes.py : 328 | 오탐 피드백 (관리자) |
| GET | `/api/endpoint-security/events` | main.py : 902 | 엔드포인트 이벤트 목록 (관리자 전용, 일반 사용자는 빈 목록) |
| POST | `/api/endpoint-security/events` | main.py : 925 | 엔드포인트 이벤트 기록 (에이전트) |

**기기 등록 · 상태 · 연결 요청**

| 메서드 | 경로 | 파일 : 줄 | 설명 |
|---|---|---|---|
| GET | `/api/ai/whoami` | ai_routes.py : 413 | 이 브라우저 기기의 등록 여부와 서버가 본 IP |
| POST | `/api/ai/register-request` | ai_routes.py : 424 | 브라우저 기기 등록 요청 |
| GET | `/api/ai/pending-devices` | ai_routes.py : 378 | 승인 대기 기기 (관리자) |
| POST | `/api/ai/enroll` | ai_routes.py : 382 | 기기 승인 (관리자) |
| POST | `/api/ai/heartbeat` | ai_routes.py : 462 | 응답 시간 보고 |
| GET | `/api/ai/connectivity` | ai_routes.py : 615 | 기기별 연결 상태 |
| POST | `/api/ai/connect-request` | ai_routes.py : 563 | 기기 간 연결 요청 (관리자) |
| GET | `/api/ai/my-connect-request` | ai_routes.py : 581 | 나에게 온 연결 요청 |
| POST | `/api/ai/connect-respond` | ai_routes.py : 590 | 연결 요청 응답 |

**에이전트 (X-API-Key)**

| 메서드 | 경로 | 파일 : 줄 | 설명 |
|---|---|---|---|
| POST | `/api/agent/pair-request` | agent_link.py : 136 | 연결 코드 발급 또는 연결 여부 확인 |
| POST | `/api/agent/telemetry` | agent_link.py : 313 | PC 측정값 보고 |
| POST | `/api/agent/hello` | ai_routes.py : 347 | 기기 등록 확인 |
| POST | `/api/agent/suspect` | ai_routes.py : 358 | 의심 프로세스 보고 |
| GET | `/api/agent/commands` | ai_routes.py : 363 | 승인된 차단 명령 가져오기 |
| POST | `/api/agent/commands/{id}/result` | ai_routes.py : 368 | 차단 결과 보고 |
| GET | `/api/agent/fleet` | agent_link.py : 214 | 최근 60초 안의 전체 장비 CPU·메모리와 평균 (본체 collector 표시용) |

**접근 · PC 승인 (관리자)**

| 메서드 | 경로 | 파일 : 줄 | 설명 |
|---|---|---|---|
| GET | `/api/access/requests` | agent_link.py : 248 | 승인 대기 목록 (구역 권한이 없는 신규 사용자, 승인되지 않은 PC) |
| POST | `/api/access/approve-user` | agent_link.py : 261 | 신규 사용자에게 구역 접근 승인 |
| POST | `/api/access/reject-user` | agent_link.py : 272 | 가입 거절 (신규 가입자 계정 삭제) |
| POST | `/api/access/approve-pc` | agent_link.py : 283 | 새 PC를 특정 사용자에게 승인 (그 사용자만 코드 입력 가능) |
| GET | `/api/link/pending` | agent_link.py : 230 | 코드 입력을 기다리는 PC 목록 (관리자는 전체, 사용자는 본인에게 승인된 것만) |

**시연 장애 시뮬레이션 (`sim_routes.py`)**

| 메서드 | 경로 | 파일 : 줄 | 권한 | 설명 |
|---|---|---|---|---|
| POST | `/api/sim/inject` | sim_routes.py : 339 | 관리자 | 장비에 장애 시나리오 시작 |
| POST | `/api/sim/device-inject` | sim_routes.py : 346 | 기기 ID | 자기 기기에만 장애 시작 (8초 쿨다운, 동시 30개) |
| GET | `/api/sim/my-status` | sim_routes.py : 563 | 기기 ID | 내 상태 (normal, warning, mitigated, resolved, blocked, pending, rejected, none) |
| GET | `/api/sim/speedtest` | sim_routes.py : 383 | 기기 ID | 속도 측정용 무작위 데이터 (최대 1MB, 5초 쿨다운) |
| POST | `/api/sim/device-disconnect` | sim_routes.py : 399 | 기기 ID | 장애 중 스스로 연결 끊기 |
| POST | `/api/sim/device-reconnect-request` | sim_routes.py : 421 | 기기 ID | 차단된 기기가 재연결 요청 (해제는 관리자만) |
| GET | `/api/sim/status` | sim_routes.py : 545 | 로그인 | 진행 중 시뮬레이션과 차단 목록 (본인 장비 범위) |
| POST | `/api/sim/mitigate` | sim_routes.py : 450 | 관리자 | 위험도 완화 |
| POST | `/api/sim/block` | sim_routes.py : 470 | 관리자 | 연결 차단 |
| POST | `/api/sim/unblock` | sim_routes.py : 490 | 관리자 | 차단 해제 (재연결 승인) |
| POST | `/api/sim/resolve` | sim_routes.py : 507 | 관리자 | 해결 완료 |
| POST | `/api/sim/reset` | sim_routes.py : 523 | 관리자 | 시뮬레이션 초기화 |
| POST | `/api/sim/reject-request` | sim_routes.py : 437 | 관리자 | 기기 등록 요청 거절 |

> 권한의 "기기 ID"는 로그인 없이 `X-Device-Id` 헤더로 식별되는 본인 기기만 사용할 수 있다는 뜻입니다.

**백업 · 상태**

| 메서드 | 경로 | 파일 : 줄 | 설명 |
|---|---|---|---|
| GET | `/api/admin/backup` | ai_routes.py : 483 | 백업 JSON 다운로드 (관리자) |
| POST | `/api/admin/restore` | ai_routes.py : 504 | 백업 복구 (`RESTORE` 입력 필요) |
| GET | `/api/health` | main.py : 957 | 서버 상태 (HEAD 요청도 허용) |
| GET | `/api/health/db` | main.py : 963 | DB까지 확인 (HEAD 허용, DB 응답이 없으면 503) — 외부 모니터링용 |
| GET | `/api/admin/db-test` | main.py : 973 | DB 연결 확인 (관리자) |

</details>

<details>
<summary><b>9. 환경변수 (이름과 설명)</b></summary>

숫자 환경변수(`JWT_EXPIRE_MINUTES`, `LOGIN_MAX_ATTEMPTS`, `LOGIN_BLOCK_MINUTES`, `AI_CONFIRM_COUNT`)에 숫자가 아닌 값(예: `720분`)을 넣으면 서버가 죽지 않고 기본값을 쓰며 로그에 경고를 남깁니다. 서버는 시작할 때 적용된 값을 `[config]` 로그로 한 줄 출력합니다.

| 이름 | 쓰는 곳 | 기본값 | 설명 |
|---|---|---|---|
| `DATABASE_URL` | 서버 | (필수) | DB 접속 주소. 없으면 서버가 시작하지 않음 |
| `JWT_SECRET` | 서버 | (필수) | 로그인 토큰 서명 키. 없으면 서버가 시작하지 않음 |
| `AGENT_API_KEY` | 서버, 에이전트 | (필수) | 에이전트 인증 키. 없으면 서버가 시작하지 않음 |
| `JWT_ALGORITHM` | 서버 | HS256 | 토큰 알고리즘 (건드리지 않음) |
| `JWT_EXPIRE_MINUTES` | 서버 | 30 | 토큰 유효 시간(분). 전시 중에는 720 권장, 끝나면 30으로 |
| `LOGIN_MAX_ATTEMPTS` | 서버 | 10 | 한 계정이 이 횟수만큼 틀리면 잠금 |
| `LOGIN_BLOCK_MINUTES` | 서버 | 60 | 잠금 시간(분). 전시 중에는 5 권장 (서버를 재시작하면 모두 풀림) |
| `AI_CONFIRM_COUNT` | 서버 | 2 | 최신 측정값이 이 횟수만큼 연속으로 이상일 때만 AI 경보 생성 (1 = 바로 경보) |
| `AI_TRAIN_DEVICE_ID` | 서버 | (비움) | AI 학습에 쓸 장비 ID. 비우면 전체 장비의 최근 측정값 사용 |
| `AUTO_ENROLL_VLAN` | 서버 | (비움) | 설정하면 기기 등록을 **승인 없이** 바로 처리. 시연이 아니면 비워 둘 것 |
| `DEFAULT_VLAN_ID` | 서버 | 1 | 새 PC의 기본 구역 ID |
| `ADMIN_AGENT_IDS` | 서버 | (비움) | 코드 없이 관리자 소유로 자동 연결할 PC ID 목록 (쉼표로 구분) |
| `ADMIN_USERNAME` | 서버 | (비움) | 자동 연결 대상 관리자 계정 이름 (비우면 가장 먼저 만든 관리자) |
| `BACKEND_URL` | 에이전트 | | 서버 주소 |
| `COLLECT_DEVICE_NAME` | collector | | PC 표시 이름 |
| `COLLECT_INTERVAL_SEC` | collector | 5 | 측정 주기(초) |
| `PING_TARGET` | collector, pinger | 8.8.8.8 | 패킷 손실 측정 대상 |
| `SCAN_SUBNET` | scanner | | 탐색 대역, 비우면 이 PC 기준 /24 |
| `IGNORE_IPS` | scanner | | 탐색 결과에서 제외할 IP 목록 |

</details>

<details>
<summary><b>10. 데이터베이스 테이블</b></summary>

| 테이블 | 역할 | 주요 컬럼 |
|---|---|---|
| `users` | 사용자 계정 | username, password_hash, role (admin / user) |
| `vlans` | 구역 | code, name, cidr, color |
| `devices` | 장비 (PC, 기기) | name, ip, type, owner_id, x, y, client_uuid, vlan_id |
| `links` | 장비 간 연결선 | source_id, target_id |
| `telemetry` | 측정값 | device_id, cpu_usage, ram_usage, traffic_in_mbps, packet_loss |
| `alerts` | 알림 | lv, title, msg, cause, action, **device_id** (경보가 가리키는 장비, 일반 사용자는 본인 장비 경보만 조회) |
| `alert_devices` | 알림과 장비 연결 | alert_id, device_id |
| `user_vlans` | 사용자별 구역 권한 (관리자 승인 시 생성) | user_id, vlan_id, access_level |
| `endpoint_events` | 엔드포인트 보안 이벤트 | action, process_name, pid, reason |
| `ai_incidents` | AI 경보 | device_id, risk_score, status, process_name, pid |
| `ping_logs` | 응답 시간 기록 | device_id, ok, rtt_ms |
| `device_blocks` | 시연 연결 차단 목록 (서버가 처음 필요할 때 자동 생성) | device_id, reason, blocked_at |
| `virtual_devices` | 전시용 가상 장비 목록 (`seed_virtual_devices.py`·서버가 자동 생성) | device_id |
| 뷰 `v_latest_telemetry` | 장비별 최신 측정값 1건 | |

**Python import 규칙** (서버 파일 `main.py`, `ai_routes.py`, `sim_routes.py`, `agent_link.py`)
- 서버는 두 방식으로 실행됩니다. Render는 `src.backend.main`(패키지), 로컬은 `src\backend`에서 `main`(직접 실행)입니다. 한 방식만 맞추면 다른 쪽이 `ModuleNotFoundError`로 죽습니다.
- 같은 폴더의 파일을 import할 때는 아래 형식만 씁니다.
```python
try:
    from .ai_routes import build_ai_router            # Render: src.backend 패키지로 실행
except ImportError:
    from ai_routes import build_ai_router             # 로컬: src\backend에서 직접 실행
```
- 절대 import(`from ai_routes import ...`)만 쓰면 Render에서, 상대 import(`from .ai_routes import ...`)만 쓰면 로컬에서 실패합니다.
- 새 파일을 추가하거나 import를 바꾼 뒤에는 Render 방식과 로컬 방식을 둘 다 실행해 봅니다.

**DB 변경 규칙**
- 운영 DB 변경은 `migrations/` 파일로만 합니다. 실행 전에 백업을 받습니다.
- `migrations/003_alerts_device_id.sql`(경보 `device_id` 컬럼)은 서버가 시작할 때 같은 변경을 자동으로 적용합니다. 직접 실행해도 안전합니다(여러 번 실행 가능).
- 새로 설치할 때 쓰는 `schema.sql`의 `alerts` 정의에도 `device_id INT NULL`과 인덱스(`idx_alerts_device`)를 넣어야 합니다.
- `schema.sql`은 맨 위에 `DROP TABLE`이 있어서 운영 DB에 실행하면 모든 데이터가 지워집니다.

</details>

<details>
<summary><b>11. 설계 핵심</b></summary>

**기기 식별**
- 브라우저는 UUID를 만들어 `X-Device-Id` 헤더로 보냅니다.
- PC는 `agent_id.txt`의 ID를 씁니다. 두 값 모두 `devices.client_uuid`에 저장됩니다.
- 같은 공인 IP를 쓰는 기기도 서로 구분됩니다. 화면의 IP는 서버가 본 공인 IP(`X-Forwarded-For` 첫 값)라서 표시용이고, 식별에는 쓰지 않습니다.

**측정 구분**
- PC: 실제 CPU, 메모리, 트래픽, 패킷 손실
- 스마트폰, 아이패드: 서버까지의 응답 시간과 실패 여부만

**권한과 개인정보**
- 관리자: 모든 장비·경보
- 일반 사용자: `devices.owner_id`가 본인인 장비와 그 장비의 경보만. 서버에서 걸러내며 화면에서 숨기는 것이 아닙니다.
- QR 기기 등록을 승인하면 장비 소유자는 승인한 관리자로 저장됩니다. 일반 계정이 그 장비를 보려면 관리자가 장비 수정에서 소유자를 바꿔야 합니다.

**연결 코드**
- 서버 메모리에 보관합니다. 관리자가 승인한 사용자만 입력할 수 있고, 한 번 사용하면 삭제합니다.
- 컬렉터가 켜져 있는 동안은 만료가 계속 연장됩니다.

**서버 상태 저장 위치**
- DB: 사용자, 장비, 측정값, 경보, 연결 차단 목록
- 서버 메모리(재시작하면 사라짐): 기기 승인 대기, 연결 코드, 차단 명령, 로그인 실패 기록, 시연 장애 상태, 등록 거절 안내, 재연결 요청

**AI 경보와 오탐 줄이기**
- 이상 판정은 `detector.py`가 하고, 경보는 같은 장비의 최신 측정값이 연속으로 이상일 때만 만듭니다(`AI_CONFIRM_COUNT`).
- 폰에서 누르는 시연 장애는 `sim_routes.py`가 경보를 직접 만들기 때문에 이 확인 횟수의 영향을 받지 않고 바로 뜹니다.
- 서버가 끊겼다 돌아온 직후 60초 동안은 화면에서 자동 경보(오프라인·AI 이상 감지)와 팝업을 보류합니다. 화면 수준의 처리라서 DB에는 기록될 수 있습니다.

**회원 탈퇴**
- 계정과 구역 권한은 삭제합니다.
- 연결된 PC는 삭제하지 않고 소유자만 비웁니다. 이후 다시 연결할 수 있습니다.

</details>

<details>
<summary><b>12. 알려진 한계</b></summary>

1. **서버 메모리 상태**: 기기 승인 대기, 연결 코드, 차단 명령, 로그인 실패 기록, 시연 장애 상태, 재연결 요청은 서버 메모리에만 있습니다. 서버가 재시작되면 사라집니다(연결 차단 목록만 DB에 남음). 인스턴스와 워커는 1개로 실행해야 합니다.
2. **무료 플랜**: Render 무료 플랜은 잠들거나 재시작될 수 있어서 첫 요청이 느리거나 실패할 수 있습니다. 전시처럼 장시간·다수 접속에는 유료 인스턴스를 권장합니다. 또한 Aiven의 무료 MySQL은 2026년 12월 21일에 종료되어 데이터가 삭제될 예정이니 유료(Developer) 플랜 등으로 옮기고 백업을 받아 두세요. ([Aiven 안내](https://aiven.io/docs/products/mysql/howto/mysql-free-tier-migration-options))
3. **공유 에이전트 키**: 모든 PC가 `AGENT_API_KEY` 하나를 씁니다. PC마다 키를 나누는 것은 향후 과제입니다.
4. **로그인 잠금**: 실패 횟수를 계정명 기준으로 셉니다. 다른 사람이 같은 계정을 잠글 수 있어서 전시 중에는 `LOGIN_BLOCK_MINUTES`를 짧게 두는 것을 권장합니다. 서버를 재시작하면 모두 풀립니다.
5. **토큰 만료**: 토큰은 `JWT_EXPIRE_MINUTES`(기본 30분) 뒤 만료되고 자동으로 연장되지 않습니다. 만료되면 안내와 함께 로그인 1단계로 돌아갑니다. 탈퇴한 사용자의 토큰은 만료 전까지 남지만, PC 연결 API에서 계정 존재 여부를 확인합니다.
6. **백업 복구**: 복구하면 장비가 지워지면서 측정 기록도 함께 사라집니다.
7. **Windows 명령 사용**: `collector.py`, `agent.py`, `scanner.py`, `pinger.py`의 ping, arp 옵션은 Windows 기준입니다.
8. **다른 PC의 차단**: `agent.py`의 차단 실행은 노트북에서 확인되었습니다. 다른 PC에서는 아직 연결 코드 방식으로 바뀌지 않았습니다.
9. **레거시 API**: `/api/devices/pending`, `/api/devices/enroll`, `/api/dashboard/overview`는 `devices.status` 컬럼을 사용하는데 현재 스키마에 없어서 호출하면 500이 납니다. 화면에서는 호출하지 않습니다.
10. **"지켜보기"는 화면 표시만 바꿉니다**: 서버의 AI 경보(`ai_incidents`)는 열린 상태 그대로이고, 오탐 처리·차단·완화로 닫아야 사라집니다. 브라우저를 새로고침하면 미룸·지켜보기 상태는 초기화됩니다.
11. **엔드포인트 이벤트**: 장비별로 구분하는 컬럼이 없어서 일반 사용자에게는 보여 주지 않고 관리자 전용으로 처리합니다.
12. **시연의 연결 차단은 논리 차단**: 화면과 상태만 바꾸며 공유기·방화벽을 제어하지 않습니다.
13. **AI 오탐과 재학습**: 경보 팝업의 오탐/재학습을 누르면 AI가 장애 수치를 정상으로 학습하므로 시연 중에는 누르지 않습니다. AI 위험도는 측정값이 50건 이상 쌓여야 동작하고, 서버를 재시작하면 모델을 다시 학습합니다.
14. **예전 경보**: `alerts.device_id` 도입 전에 쌓인 경보는 장비 정보가 없어 관리자만 볼 수 있습니다.
15. **기기 IP**: 웹은 기기의 내부 IP(192.168.x.x)를 읽을 수 없어서 서버가 본 공인 IP를 표시합니다. 같은 와이파이의 기기는 같은 값입니다.

</details>

<details>
<summary><b>13. 보안 주의사항</b></summary>

- `.env`, `backup/`, `agent_id.txt`는 저장소에 올리지 않습니다. `.gitignore`에 있어도 이미 추적 중인 파일은 제외되지 않으니 `git ls-files`로 확인하세요.
- 비밀번호, 토큰, DB 주소를 캡처하거나 채팅에 붙여 넣지 마세요. 진단할 때는 값을 `***`로 가린 출력만 씁니다.
- 백업 파일(JSON, SQL)에는 계정 해시가 들어 있습니다. 개인 매체에만 보관하세요.
- 과거 커밋에 `.env`나 `backup/` 파일이 남아 있을 수 있습니다. 저장소를 공개하기 전에 기록을 정리하세요.
- 일반 사용자에게 다른 사람의 장비·경보·계정 목록·프로세스 이벤트가 보이지 않도록 `/api/alerts`, `/api/users`, `/api/endpoint-security/events`를 서버에서 걸러냅니다. 새 조회 API를 만들 때도 같은 기준을 지키세요.
- 접속 IP는 `X-Forwarded-For`의 첫 값을 씁니다. 값을 위조할 수 있으므로 표시와 가입 횟수 제한에만 쓰고 인증에는 쓰지 않습니다.
- `AUTO_ENROLL_VLAN`이 설정되면 기기가 승인 없이 등록됩니다. 시연이 아니면 비워 두세요.

</details>

<details>
<summary><b>14. 시연 전 확인 목록</b></summary>

**기본 동작**
- [ ] Render 배포가 성공했고 시작 에러가 없음 (Logs에서 `[config]` 줄 확인)
- [ ] `/api/health`, `/api/health/db` 응답 확인
- [ ] 회원가입 → 관리자 승인 → 로그인 → 구역 선택 → 대시보드 진입
- [ ] 새 PC 연결 후 측정값 표시
- [ ] 일반 사용자 계정에서는 본인 장비와 경보만 보임
- [ ] 관리자 계정에서는 전체 장비가 보임
- [ ] 차단 흐름: 탐지 → 승인 → 종료 확인
- [ ] 노트북 절전 해제, `AUTO_ENROLL_VLAN` 비어 있음
- [ ] 브라우저에서 `Ctrl+F5` 후 다시 로그인

**시연 흐름**
- [ ] QR로 폰 접속 → 등록 요청 → 관리자 승인(와 거절) → 장애 패널 표시
- [ ] 폰에서 장애 → 본체 팝업 → 완화/차단 → 해결/해제, 폰 단계 배너 확인
- [ ] 같은 와이파이에서 기기 2대를 연달아 등록해도 모두 승인됨
- [ ] 폰 자동 잠금 끄기, QR 인쇄 전 폰으로 테스트
- [ ] 정상 동작 영상 2~3분 녹화 (서버가 완전히 멈출 때의 대비)

**서버 설정** (자세한 내용은 [docs/EXHIBITION.md](docs/EXHIBITION.md))
- [ ] `JWT_EXPIRE_MINUTES=720`, `LOGIN_BLOCK_MINUTES=5` 저장 후 로그에서 적용 확인
- [ ] Render Health Check Path `/api/health`, 마지막 배포 뒤 Auto-Deploy 끄기
- [ ] UptimeRobot 모니터 2개가 Up이고 테스트 알림이 도착함
- [ ] Aiven DB 플랜 확인과 `mysqldump` 백업
- [ ] 2시간 이상 동시 접속 리허설

</details>

<details>
<summary><b>15. 전시 운영 가이드</b></summary>

설정 정리, 전시 전·중·후 체크리스트, 장애 대응 순서, 설명 스크립트와 예상 질문은 [docs/EXHIBITION.md](docs/EXHIBITION.md)에 있습니다.

</details>


---

## 실행 방법

이 섹션은 두 가지 실행 방법을 설명합니다.
- **A. 장비(노트북)에서 직접 실행** — 전시와 시연에 쓰는 방법
- **B. 클라우드(Render)에서 실행** — 인터넷 주소로 접속하는 방법

비밀 값(비밀번호, 키, 토큰)은 이 문서에 적지 않습니다. `.env`에만 넣고 Git에 올리지 마세요.

### A. 장비(노트북)에서 직접 실행

**1) 사전 준비 (한 번만)**
- Python 3.10 이상, MySQL 8.0 설치
- MySQL에 `netmon` 데이터베이스와 계정 생성 (`schema.sql` 또는 서버 최초 실행으로 테이블 생성)
- 라이브러리 설치
  ```powershell
  cd "프로젝트 경로\src\backend"
  pip install -r requirements.txt
  ```

**2) `.env` 설정 (`src\backend\.env`)**

| 키 | 설명 | 로컬 값 예시 |
|---|---|---|
| `DATABASE_URL` | DB 연결 주소 | `mysql+pymysql://netmon:<DB 비밀번호>@127.0.0.1:3306/netmon` |
| `BACKEND_URL` | 수집기와 에이전트가 서버를 찾는 주소 | `http://127.0.0.1:8000` |
| `JWT_SECRET` | 로그인 토큰 서명 키 | 직접 생성한 긴 문자열 |
| `AGENT_API_KEY` | 에이전트 인증 키 | 직접 생성한 긴 문자열 |
| `COLLECT_DEVICE_NAME` | 이 PC를 부르는 이름 | `JIHYAN` |
| `COLLECT_VLAN_ID` | 이 PC가 속한 구역 번호 | `100` |

값 자체는 `.env`에서만 확인하세요. `.env`를 바꾼 뒤에는 실행 중인 프로그램을 모두 껐다가 다시 켜야 합니다.

**3) 실행 (터미널 4개, 각각 `src\backend`에서)**

| 터미널 | 역할 | 명령 |
|---|---|---|
| 1 | 서버 (웹 화면) | `uvicorn main:app --host 0.0.0.0 --port 8000` |
| 2 | 수집기 (CPU·메모리·트래픽) | `python collector.py` |
| 3 | 핑 (장비 연결 상태) | `python pinger.py` |
| 4 (선택) | 차단 에이전트 (시연용) | `python agent_ai.py` |

`--host 0.0.0.0`이 있어야 같은 Wi-Fi의 아이패드가 접속할 수 있습니다.

**4) 접속**
- 노트북 브라우저: `http://127.0.0.1:8000/?env=real` (관리자 계정으로 로그인)
- 아이패드(같은 Wi-Fi): `http://노트북IP:8000/?env=real`
  - 노트북 IP는 `ipconfig`의 무선 LAN IPv4 주소입니다.
  - 아이패드의 "비공개 Wi-Fi 주소"는 꺼 두세요.

**5) 외부에서 QR로 접속하게 하기 (선택)**
- 노트북 서버를 인터넷 임시 주소로 여는 방법입니다. 실행할 때마다 주소가 바뀝니다.
  ```powershell
  winget install --id Cloudflare.cloudflared
  cloudflared tunnel --url http://localhost:8000
  ```
- 출력된 `https://....trycloudflare.com` 주소를 QR로 만듭니다. 뒤에 `/?env=real`을 붙입니다.
- 관람객에게 관리자 계정을 주지 마세요. 일반 계정을 따로 준비하세요.
- 전시가 끝나면 `Ctrl+C`로 터널을 끄세요.

### B. 클라우드(Render)에서 실행

- 서비스 형태: Render Web Service (Python)
- 시작 명령: `PYTHONPATH=. uvicorn src.backend.main:app --host 0.0.0.0 --port $PORT`
- 환경 변수 이름: `DATABASE_URL`, `BACKEND_URL`, `JWT_SECRET`, `AGENT_API_KEY` (값은 Render의 Environment 화면에서 직접 입력)
- `DATABASE_URL`은 클라우드 DB의 호스트, 포트, 사용자, 비밀번호, DB 이름(`netmon`), SSL 옵션을 모두 포함해야 합니다.

**한계**
- Render 서버는 노트북 CPU·메모리를 측정할 수 없습니다. `collector.py`는 **실행한 PC**만 측정합니다.
- 내부 IP(192.168.x.x)로 하는 핑 측정은 Render에서 실패합니다.
- 클라우드 DB는 유료 플랜과 데이터 이관이 필요합니다.

### 실행 확인 체크리스트

- [ ] 서버 터미널에 `Uvicorn running on http://0.0.0.0:8000`이 나온다
- [ ] 수집기 터미널에 `cpu=…% ram=…%`가 주기적으로 나온다
- [ ] 관리자 계정으로 로그인되고 장비 목록이 보인다
- [ ] 아이패드에서 노트북 IP 주소로 화면이 열린다

### 문제 해결

| 증상 | 원인 | 해결 |
|---|---|---|
| `getaddrinfo failed` | `DATABASE_URL`의 호스트를 찾지 못함 | 호스트 주소 확인, 로컬은 `127.0.0.1` |
| `Access denied` | DB 비밀번호 불일치 | `DATABASE_URL`의 비밀번호 확인 |
| `503 Server Error` (수집기) | `BACKEND_URL`이 꺼진 서버를 가리킴 | `BACKEND_URL=http://127.0.0.1:8000`으로 수정 |
| `ModuleNotFoundError` / `relative import` | 실행 위치 또는 import 방식 불일치 | `src\backend`에서 실행, 9장 import 규칙 준수 |
| 아이패드 접속 불가 | 서버가 `127.0.0.1`로만 실행됨 | `--host 0.0.0.0`으로 다시 실행, 방화벽 허용 |


---

## 설정 가이드 1: 장비(노트북)에서 설정하기

노트북 한 대에서 서버, DB, 수집기를 모두 돌리는 방법입니다. 전시와 시연의 기본 구성입니다.

### 1-1. 프로그램 설치 (한 번만)
1. **Python 3.10 이상** 설치 (설치 시 "Add to PATH" 체크)
2. **MySQL 8.0** 설치
3. 프로젝트 라이브러리 설치
   ```powershell
   cd "프로젝트 경로\src\backend"
   pip install -r requirements.txt
   ```

### 1-2. MySQL 준비 (한 번만)
MySQL에 접속해 DB와 계정을 만듭니다. 비밀번호는 본인이 정하고 `.env`에 같은 값을 넣습니다.
```powershell
& "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -u root -p
```
```sql
CREATE DATABASE netmon DEFAULT CHARACTER SET utf8mb4;
CREATE USER 'netmon'@'localhost' IDENTIFIED BY '<새 비밀번호>';
GRANT ALL PRIVILEGES ON netmon.* TO 'netmon'@'localhost';
FLUSH PRIVILEGES;
```
- 테이블은 서버를 처음 켤 때 대부분 자동으로 만들어집니다. 필요하면 `schema.sql`을 실행합니다.

### 1-3. `.env` 설정 (`src\backend\.env`)
| 키 | 값 (로컬) | 비고 |
|---|---|---|
| `DATABASE_URL` | `mysql+pymysql://netmon:<DB 비밀번호>@127.0.0.1:3306/netmon` | 호스트는 반드시 `127.0.0.1` |
| `BACKEND_URL` | `http://127.0.0.1:8000` | 수집기가 서버를 찾는 주소 |
| `JWT_SECRET` | 새로 만든 긴 문자열 | 아래 명령으로 생성 |
| `AGENT_API_KEY` | 새로 만든 긴 문자열 | 에이전트 인증용 |
| `COLLECT_DEVICE_NAME` | 이 PC 이름 (예: `JIHYAN`) | |
| `COLLECT_VLAN_ID` | 구역 번호 (예: `100`) | |

키 생성 명령:
```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```
- `.env`는 Git에 올리지 않습니다.
- 값을 바꾼 뒤에는 실행 중인 프로그램을 모두 끄고 다시 켭니다.

`.env` 전체 구조 예시 (비밀 값은 `(값)`으로 가림):

```
# ── 데이터베이스 ──
DATABASE_URL=mysql+pymysql://netmon:(DB 비밀번호)@127.0.0.1:3306/netmon

# ── 서버 주소 ──
BACKEND_URL=http://127.0.0.1:8000

# ── 보안 키 (직접 생성, 공유 금지) ──
JWT_SECRET=(긴 임의 문자열)
AGENT_API_KEY=(긴 임의 문자열)

# ── 이 PC 수집 설정 ──
COLLECT_DEVICE_NAME=JIHYAN
COLLECT_VLAN_ID=100
COLLECT_INTERVAL_SEC=5
PING_TARGET=8.8.8.8
```

- `(값)` 부분만 본인 값으로 바꾸면 됩니다. 괄호는 빼고 입력하세요.
- 이 파일은 Git에 올리지 않습니다.
- Render에는 같은 키 이름을 쓰되, `DATABASE_URL`과 `BACKEND_URL`만 클라우드 값으로 바꿉니다.

### 1-4. 실행 (터미널 3~4개, 모두 `src\backend`에서)
```powershell
cd "프로젝트 경로\src\backend"
```
| 터미널 | 명령 |
|---|---|
| 1 서버 | `uvicorn main:app --host 0.0.0.0 --port 8000` |
| 2 수집기 | `python collector.py` |
| 3 핑 | `python pinger.py` |
| 4 차단 에이전트 (선택) | `python agent_ai.py` |

### 1-5. 아이패드·다른 기기 접속 설정
1. 노트북 IP 확인: `ipconfig` → 무선 LAN IPv4 주소
2. 방화벽 허용 (관리자 PowerShell, 한 번만)
   ```powershell
   New-NetFirewallRule -DisplayName "NetMon 8000" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow -Profile Any
   ```
   시연 후 제거: `Remove-NetFirewallRule -DisplayName "NetMon 8000"`
3. 아이패드를 **노트북과 같은 Wi-Fi**에 연결
4. 아이패드 "비공개 Wi-Fi 주소" 끄기
5. 아이패드 브라우저: `http://노트북IP:8000/?env=real`

**IP가 바뀌었을 때:** 노트북 IP를 다시 확인하고, 아이패드 주소를 새 값으로 입력합니다.

### 1-6. 외부 QR 접속 (선택)
```powershell
cloudflared tunnel --url http://localhost:8000
```
- 출력된 주소에 `/?env=real`을 붙여 QR로 만듭니다.
- 전시 시간에만 실행하고, 끝나면 `Ctrl+C`로 종료합니다.
- 관람객에게는 **일반 계정**만 안내합니다.

---

## 설정 가이드 2: 클라우드(Render + Aiven)에서 설정하기

인터넷 주소로 어디서든 접속하는 방법입니다. 비용이 발생하고, 노트북 CPU 측정은 되지 않습니다.

### 2-1. Aiven MySQL 준비
1. Aiven 콘솔에서 **MySQL 서비스 생성** (유료 플랜, 지역은 Render와 가까운 곳 권장)
2. 서비스 상태가 **Running**인지 확인 (Powered off면 켜야 함)
3. **Databases** 탭에서 `netmon` 생성
4. **Connection information**에서 확인:
   - Host, Port, User, Password, Database name
5. **CA certificate**를 Download해서 저장 (`ca.pem`)
6. 로컬 DB를 옮기려면 덤프 후 가져오기 (이관 절차는 별도 메모 참고)

### 2-2. Render 웹 서비스 준비
1. Render에서 **New → Web Service**, 이 저장소 연결
2. 설정:
   - Runtime: Python
   - Build command: `pip install -r requirements.txt`
   - Start command: `PYTHONPATH=. uvicorn src.backend.main:app --host 0.0.0.0 --port $PORT`
3. **Environment** 탭에 아래 이름으로 값을 입력 (값은 화면에만 입력, 채팅·Git에 쓰지 않음)

| 키 | 설명 |
|---|---|
| `DATABASE_URL` | Aiven 호스트·포트·사용자·비밀번호·DB 이름(`netmon`) 포함 |
| `BACKEND_URL` | 이 서비스의 Render 주소 (`https://...onrender.com`) |
| `JWT_SECRET` | 새로 생성한 긴 문자열 |
| `AGENT_API_KEY` | 새로 생성한 긴 문자열 |

### 2-3. `DATABASE_URL` 형식과 SSL
```
mysql+pymysql://<사용자>:<비밀번호>@<호스트>:<포트>/netmon?ssl_ca=<CA 파일 경로>
```
- **SSL이 필수**입니다. `database.py`가 CA 인증서를 읽도록 되어 있는지 먼저 확인하세요. 되어 있지 않으면 설정을 추가해야 합니다.
- 포트는 Aiven 화면에 표시된 값을 그대로 씁니다.

### 2-4. 배포와 확인
1. **Manual Deploy** 또는 push 후 자동 배포를 기다립니다.
2. 로그에서 `Application startup complete`가 나오는지 확인합니다.
3. `Can't connect`나 `getaddrinfo failed`가 나오면 `DATABASE_URL`의 호스트를 확인합니다.
4. 관리자 계정으로 로그인해 장비와 알림이 보이는지 확인합니다.

### 2-5. 클라우드의 한계 (설명용)
- Render 서버는 **노트북 CPU·메모리를 측정하지 못합니다.** 수집기는 실행한 PC만 측정합니다.
- 내부 IP(192.168.x.x)로 하는 핑은 **Render에서 실패**합니다.
- 장비를 실제로 측정하려면 노트북에서 `collector.py`를 따로 실행하고, 그 PC가 Render의 DB에 쓰도록 `DATABASE_URL`을 맞춰야 합니다.

---

## 다음 할 일 목록

우선순위 순서입니다.

1. **로컬 서버 기동 확인**: 서버, 수집기, 핑을 켜고 관리자 로그인 확인
2. **노출된 키 교체**: `JWT_SECRET`, `AGENT_API_KEY`, DB 비밀번호를 새 값으로 교체 (노트북 `.env`와 Render 모두)
3. **아이패드 접속 테스트**: 같은 Wi-Fi에서 노트북 IP로 접속
4. **교대 기능 테스트**: 교대 시뮬레이션을 켜고 교대 보고 전달과 확인 현황 확인
5. **알림 기능 테스트**: 최근 알림 상세 창, 사고 보고서 열기 버튼 확인
6. **일반 계정 확인표 진행**: 인수인계 추가본 3장 항목 확인
7. **Git 커밋**: `ai_routes.py`, `index.html`, `main.py`, `sim_routes.py`, `agent_link.py`, `README.md`
8. **문서 정리**: `EXHIBITION.md`의 Render·Aiven 설명을 실제 전시 방식에 맞게 수정
9. **정리**: 전시 후 또는 필요 없으면 Render 서비스와 Aiven 서비스 정리

또한 전시 전날에는 노트북 IP 확인, 방화벽 규칙 추가, 아이패드 접속 테스트를 한 번 더 하세요.
