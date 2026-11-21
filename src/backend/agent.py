# -*- coding: utf-8 -*-
"""엔드포인트 보안 감시 에이전트 (노트북에서 실행, 관리자 PowerShell 권장)

흐름
1. 감시 목록과 정확히 같은 이름의 프로세스를 찾는다.
2. 처음 발견하면 (a) 탐지 이벤트를 보고하고, (b) 설정·로그 파일을 로컬 백업 폴더에 자동 백업하고,
   (c) 사고 보고(장비, 원인, 백업 결과)를 서버 /api/agent/incident 로 보낸다.
3. 같은 프로세스를 /api/agent/suspect 에 보고한다 (AI 경보와 연결됨).
4. 관리자가 대시보드에서 승인하면 /api/agent/commands 로 명령을 받아
   PID + 이름 + 생성 시각이 모두 일치할 때만 종료하고 결과를 보고한다.

환경변수 (.env, 모두 선택)
- BACKUP_DIR        백업 폴더. 비우면 agent.py 옆의 backup 폴더
- BACKUP_SOURCES    백업할 파일·폴더 경로, 쉼표로 구분. 비우면 hosts 파일만 백업
- BACKUP_MAX_MB     파일 하나의 최대 크기(MB), 기본 50
- BACKUP_COPY_EXE   1이면 의심 프로세스의 실행 파일도 복사 (기본 0 = 복사 안 함)
"""
import base64
import io
import json
import os
import shutil
import socket
import sys
import time
import zipfile
from datetime import datetime
from pathlib import Path

import psutil
import requests
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

BACKEND = os.getenv("BACKEND_URL", "https://cusor-8bit.onrender.com").rstrip("/")
AGENT_KEY = os.getenv("AGENT_API_KEY")
if not AGENT_KEY:
    sys.exit("AGENT_API_KEY가 .env에 없습니다.")
HEADERS = {"X-API-Key": AGENT_KEY}

INTERVAL = 5  # 초
REQUEST_TIMEOUT = 20  # 초. 무료 서버가 느릴 때를 위해 넉넉하게

# ---- 장비 백업 설정 ----
BACKUP_INTERVAL_SEC = int(float(os.getenv("BACKUP_INTERVAL_HOURS") or "12") * 3600)  # 기본 12시간
BACKUP_UPLOAD_MAX = 5 * 1024 * 1024   # 서버 보관 상한(5MB)과 같게
BACKUP_LOCAL_KEEP = 5                 # PC 폴더에 두는 개수
last_backup_at = 0.0                  # 마지막 백업 시각 (0 = 아직 없음)

# 감시 목록: 이름이 정확히 같을 때만 탐지 (부분 문자열 매칭 금지)
SUSPICIOUS_NAMES = {"nc.exe", "psexec.exe", "mimikatz.exe", "backdoor.exe", "ransomware.exe"}

# 종료하면 안 되는 시스템 프로세스 (이름 기준, 소문자)
PROTECTED_NAMES = {
    "system", "system idle process", "registry", "memory compression",
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "svchost.exe", "explorer.exe",
}

# ---- 자동 백업 설정 ----
BACKUP_ROOT = Path(os.getenv("BACKUP_DIR") or (BASE_DIR / "backup"))
BACKUP_SOURCES = [s.strip() for s in
                  (os.getenv("BACKUP_SOURCES") or r"%SystemRoot%\System32\drivers\etc\hosts").split(",")
                  if s.strip()]
BACKUP_MAX_BYTES = int(os.getenv("BACKUP_MAX_MB") or "50") * 1024 * 1024
BACKUP_COPY_EXE = (os.getenv("BACKUP_COPY_EXE") or "0").strip() == "1"

device_id = None          # 서버에서 받은 이 PC의 장비 id
reported_pids = set()     # 이미 탐지·백업한 프로세스 id
pending_incidents = []    # 서버에 아직 못 보낸 사고 보고 (연결이 돌아오면 다시 보냄)


def local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # 패킷은 보내지 않고 인터페이스만 고른다
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def api(method: str, path: str, **kwargs):
    r = requests.request(method, BACKEND + path, headers=HEADERS, timeout=REQUEST_TIMEOUT, **kwargs)
    r.raise_for_status()
    return r.json()


def ensure_device_id() -> None:
    """hello 호출로 이 PC의 device_id를 얻는다. 미등록이면 None 유지."""
    global device_id
    if device_id is not None:
        return
    r = api("POST", "/api/agent/hello", json={"ip": local_ip(), "hostname": socket.gethostname()})
    if r.get("registered"):
        device_id = r["device_id"]
        print(f"[agent] 장비 확인: device_id={device_id}")
    else:
        print("[agent] 아직 미등록 장비입니다. 대시보드에서 등록 승인 후 다시 시도합니다.")


def is_protected(pid: int, name_lower: str) -> bool:
    return pid is None or pid <= 4 or pid == os.getpid() or name_lower in PROTECTED_NAMES


def send_event(action: str, name: str, pid: int, reason: str) -> None:
    try:
        api("POST", "/api/endpoint-security/events",
            json={"action": action, "process_name": name, "pid": pid, "reason": reason})
        print(f"[agent] 이벤트 전송 | {action} | {name} | PID {pid}")
    except Exception as e:
        print(f"[agent] 이벤트 전송 실패: {e}")


def scan_suspicious() -> list[dict]:
    found = []
    for p in psutil.process_iter(["pid", "name", "create_time"]):
        try:
            info = p.info
            name = info["name"] or ""
            if is_protected(info["pid"], name.lower()):
                continue
            if name.lower() in SUSPICIOUS_NAMES:
                found.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return found


# ---------- 자동 백업 ----------

def _dir_size(p: Path) -> int:
    total = 0
    for root, _, files in os.walk(p):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


def make_backup(info: dict) -> dict:
    """설정·로그 파일을 백업 폴더에 복사하고 결과를 돌려준다.
    status: ok(전부 성공) / partial(일부 실패) / failed(전부 실패) / skipped(백업 대상 없음)"""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    short = (info.get("name") or "proc").replace(".exe", "")
    folder = BACKUP_ROOT / f"{stamp}_{short}_pid{info.get('pid')}"

    exe = ""
    try:
        exe = psutil.Process(info["pid"]).exe()
    except Exception:
        exe = ""

    sources = list(BACKUP_SOURCES)
    if BACKUP_COPY_EXE and exe:
        sources.append(exe)
    if not sources:
        return {"status": "skipped", "path": "", "files": []}

    try:
        folder.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        return {"status": "failed", "path": str(folder),
                "files": [{"src": "", "dst": "", "ok": False, "error": f"백업 폴더 생성 실패: {e}"}]}

    files = []
    for i, raw in enumerate(sources, 1):
        src = Path(os.path.expandvars(raw))
        dst = folder / f"{i:02d}_{src.name or 'item'}"
        rec = {"src": str(src), "dst": str(dst), "ok": False, "error": ""}
        try:
            if not src.exists():
                raise FileNotFoundError("원본 없음")
            size = src.stat().st_size if src.is_file() else _dir_size(src)
            if size > BACKUP_MAX_BYTES:
                raise ValueError(f"용량 초과({size // 1048576}MB)")
            if src.is_file():
                shutil.copy2(src, dst)
            else:
                shutil.copytree(src, dst, dirs_exist_ok=True)
            rec["ok"] = True
        except Exception as e:
            rec["error"] = str(e)[:200]
        files.append(rec)

    ok_n = sum(1 for f in files if f["ok"])
    status = "ok" if ok_n == len(files) else ("failed" if ok_n == 0 else "partial")

    manifest = {
        "process_name": info.get("name"), "pid": info.get("pid"), "suspect_exe": exe,
        "detected_at": time.strftime("%Y-%m-%d %H:%M:%S"), "status": status, "files": files,
    }
    try:
        (folder / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as e:
        print(f"[agent] manifest 저장 실패: {e}")

    return {"status": status, "path": str(folder), "files": files}


def queue_incident(info: dict, backup: dict) -> None:
    """사고 보고를 대기열에 넣는다. 실제 전송은 flush_incidents()가 한다."""
    pending_incidents.append({
        "tries": 0,
        "data": {
            "hostname": socket.gethostname(),
            "ip": local_ip(),
            "process_name": info.get("name") or "",
            "pid": info.get("pid"),
            "cause": f"Suspicious process detected: {info.get('name')}",
            "occurred_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "backup": backup,
        },
    })


def flush_incidents() -> None:
    """대기 중인 사고 보고를 서버로 보낸다. 장비 번호를 아직 모르면 기다린다."""
    if device_id is None or not pending_incidents:
        return
    for item in list(pending_incidents):
        body = {"device_id": device_id, **item["data"]}
        try:
            r = api("POST", "/api/agent/incident", json=body)
            pending_incidents.remove(item)
            print(f"[agent] 사고 보고 전송 | {item['data']['process_name']} | 보고서 ID {r.get('incident_id')}")
        except Exception as e:
            item["tries"] += 1
            if item["tries"] >= 30:
                pending_incidents.remove(item)
                print(f"[agent] 사고 보고 포기(30회 실패): {e}")
            elif item["tries"] == 1 or item["tries"] % 10 == 0:
                print(f"[agent] 사고 보고 재시도 대기 ({item['tries']}회): {e}")


# ---------- 탐지 처리 ----------

def report_suspicious(found: list[dict]) -> None:
    current = {f["pid"] for f in found}
    reported_pids.intersection_update(current)  # 끝난 프로세스는 기록에서 제거

    for info in found:
        pid, name = info["pid"], info["name"]

        if pid not in reported_pids:
            reported_pids.add(pid)
            # 1) 탐지 이벤트 로그 (처음 발견했을 때 한 번만)
            send_event("detected", name, pid, f"Suspicious process detected: {name}")
            # 2) 설정·로그 자동 백업 + 사고 보고 대기열
            backup = make_backup(info)
            print(f"[agent] 자동 백업 | {backup['status']} | {backup['path'] or '-'}")
            queue_incident(info, backup)

        # 3) 의심 프로세스 정보 (AI 경보와 연결되도록 주기적으로 갱신)
        if device_id is not None:
            try:
                api("POST", "/api/agent/suspect", json={
                    "device_id": device_id, "pid": pid, "name": name,
                    "create_time": info["create_time"], "exe": "",
                })
            except Exception as e:
                print(f"[agent] 의심 프로세스 보고 실패: {e}")


def try_kill(cmd: dict) -> tuple[bool, str]:
    """승인된 명령 실행. PID, 이름, 생성 시각이 모두 맞을 때만 종료한다."""
    if cmd.get("mode") != "kill":
        return False, f"지원하지 않는 모드: {cmd.get('mode')}"

    pid = cmd.get("pid")
    name = (cmd.get("name") or "")
    name_lower = name.lower()
    if is_protected(pid, name_lower):
        return False, "보호된 시스템 프로세스라 종료하지 않음"

    try:
        p = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return False, "프로세스가 이미 종료되어 있음"
    except psutil.AccessDenied:
        return False, "권한 부족 (관리자 PowerShell로 실행해야 함)"

    try:
        if p.name().lower() != name_lower:
            return False, "PID의 프로세스 이름이 달라 종료하지 않음"
        ct = cmd.get("create_time")
        if ct and abs(p.create_time() - ct) > 1:
            return False, "PID가 재사용되어 종료하지 않음"

        p.terminate()
        try:
            p.wait(timeout=3)
        except psutil.TimeoutExpired:
            p.kill()
            p.wait(timeout=3)
        return True, f"{name}(PID {pid}) 종료 완료"
    except psutil.AccessDenied:
        return False, "권한 부족으로 종료 실패"
    except psutil.NoSuchProcess:
        return True, f"{name}(PID {pid}) 종료 완료"


def make_backup_zip() -> bytes:
    """BACKUP_SOURCES의 파일과 폴더를 zip 하나로 묶는다. 없는 원본은 manifest에 적는다."""
    buf = io.BytesIO()
    missing = []
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for raw in BACKUP_SOURCES:
            src = Path(os.path.expandvars(raw))
            if src.is_file():
                z.write(src, arcname=src.name)
            elif src.is_dir():
                for f in src.rglob("*"):
                    if f.is_file():
                        z.write(f, arcname=f"{src.name}/{f.relative_to(src)}")
            else:
                missing.append(str(src))
        z.writestr("manifest.txt", "\n".join([
            "백업 시각: " + time.strftime("%Y-%m-%d %H:%M:%S"),
            "PC 이름: " + socket.gethostname(),
            "없는 원본: " + (", ".join(missing) or "없음"),
        ]))
    return buf.getvalue()


def run_backup(reason: str) -> None:
    """파일 백업을 만들어 PC 폴더에 저장하고, 5MB 이하면 서버에도 올린다."""
    global last_backup_at
    last_backup_at = time.time()
    if device_id is None:
        print("[backup] 아직 장비 번호가 없어 건너뜀 (승인 후 자동 실행)")
        return
    try:
        data = make_backup_zip()
    except Exception as e:
        print(f"[backup] 압축 실패: {e}")
        return
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder = BACKUP_ROOT / f"{socket.gethostname()}_{device_id}"
    try:
        folder.mkdir(parents=True, exist_ok=True)
        (folder / f"{stamp}.zip").write_bytes(data)
        for old in sorted(folder.glob("*.zip"))[:-BACKUP_LOCAL_KEEP]:
            old.unlink()
    except Exception as e:
        print(f"[backup] PC 폴더 저장 실패: {e}")
    if len(data) > BACKUP_UPLOAD_MAX:
        print(f"[backup] {len(data) // 1048576}MB로 5MB를 넘어 서버에는 올리지 않았어요 (PC 폴더에는 저장됨)")
        return
    try:
        requests.post(BACKEND + "/api/agent/backup", headers=HEADERS, timeout=120, json={
            "device_id": device_id,
            "name": f"{socket.gethostname()}_{stamp}.zip",
            "data_b64": base64.b64encode(data).decode("ascii"),
        }).raise_for_status()
        print(f"[backup] {reason} 완료 | {len(data) // 1024}KB | 서버 저장됨")
    except Exception as e:
        print(f"[backup] 서버 업로드 실패 (PC 폴더에는 저장됨, 다음 주기에 다시 시도): {e}")


def maybe_auto_backup() -> None:
    if time.time() - last_backup_at >= BACKUP_INTERVAL_SEC:
        run_backup("자동 백업")


def poll_commands() -> None:
    if device_id is None:
        return
    data = api("GET", "/api/agent/commands", params={"device_id": device_id})
    for cmd in data.get("commands", []):
        if cmd.get("mode") == "backup":          # 관리자가 누른 "지금 백업"
            run_backup("관리자 요청 백업")
            continue
        ok, detail = try_kill(cmd)
        print(f"[agent] 차단 명령 {cmd.get('id', '')[:8]} | {'성공' if ok else '실패'} | {detail}")
        api("POST", f"/api/agent/commands/{cmd['id']}/result",
            params={"incident_id": cmd["incident_id"]},
            json={"ok": ok, "detail": detail})


def check_backend() -> None:
    try:
        r = requests.get(BACKEND + "/api/health", timeout=REQUEST_TIMEOUT)
        status = r.json().get("status", "?")
        print(f"[✓] 백엔드 상태: {status}")
    except Exception as e:
        print(f"[!] 백엔드 확인 실패: {e}")


def main() -> None:
    print("=" * 60)
    print("엔드포인트 보안 감시 에이전트 시작")
    print("=" * 60)
    print(f"백엔드 URL: {BACKEND}")
    print(f"감시 프로세스: {', '.join(sorted(SUSPICIOUS_NAMES))}")
    print(f"백업 폴더: {BACKUP_ROOT}")
    print(f"백업 대상: {', '.join(BACKUP_SOURCES) or '없음'}")
    print("=" * 60)
    check_backend()

    while True:
        try:
            ensure_device_id()
            report_suspicious(scan_suspicious())
            poll_commands()
            flush_incidents()
            maybe_auto_backup()
        except Exception as e:
            print(f"[agent] 오류: {e}")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[agent] 종료합니다.")
