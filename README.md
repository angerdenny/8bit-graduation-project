# 8bit 졸업 작품: AI 기반 네트워크 관리 시스템

> 8bit 졸업 작품으로 만든 AI 기반 네트워크 모니터링·보안 관제 시스템입니다.
> 직접 설치하고 실행해 보고 싶은 후배·학생을 위해 공개합니다.

📘 **설치 가이드:** https://angerdenny.github.io/8bit-graduation-project/guide.html

## 주요 기능

- 실시간 트래픽과 장비 상태(CPU, 메모리) 모니터링
- AI 기반 장애 위험 스코어와 이상 징후 알림
- 장비 핑 확인, 보안 로그, 교대 인수인계 기록
- 장애 시뮬레이션으로 화면 동작 재현

## 빠른 시작 (로컬 실행)

1. 저장소 복제
   ```powershell
   git clone https://github.com/angerdenny/8bit-graduation-project.git
   cd 8bit-graduation-project
   pip install -r requirements.txt
   ```
2. `src/backend/.env.example`을 복사해 `src/backend/.env`를 만들고 값을 채웁니다.
   - `JWT_SECRET`, `AGENT_API_KEY`는 아래 명령으로 직접 만듭니다.
   ```powershell
   python -c "import secrets; print(secrets.token_hex(32))"
   ```
3. MySQL 8.0에 `netmon` DB를 만들고 `schema.sql`과 `migrations/`를 적용합니다.
4. `src/backend`에서 아래 3개를 각각 다른 터미널로 실행합니다.
   - `uvicorn main:app --host 0.0.0.0 --port 8000`
   - `python collector.py`
   - `python pinger.py`
5. 브라우저에서 `http://127.0.0.1:8000/`을 열고 "노트북 로컬"을 선택합니다.

자세한 순서와 사진은 [설치 가이드](https://angerdenny.github.io/8bit-graduation-project/guide.html)를 보세요.

## 클라우드 배포 (준비 중)

인터넷에서 접속하려면 Render와 Aiven 같은 클라우드 배포가 필요합니다. 현재는 로컬 실행을 기준으로 합니다.

## 주의

- `.env`, 비밀번호, 키 값은 저장소에 올리지 마세요.
- 화면의 수치(Mbps, 퍼센트, 장비 수)는 실행 환경마다 다릅니다.
- 모드 선택 창의 선택값은 브라우저에만 저장됩니다. 다시 보려면 콘솔(F12)에서 `openModePicker()`를 입력하세요.
