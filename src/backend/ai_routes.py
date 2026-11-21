"""AI 위험도 / 관리자 승인 차단 / 오탐 피드백 / 미등록 기기 감지."""
import os
import re
import hmac
import ipaddress
import json
import sys
import threading
import time
import uuid
from pathlib import Path
from datetime import datetime, timedelta, timezone
from datetime import time as _tm
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text, bindparam
from sqlalchemy.exc import IntegrityError

sys.path.append(str(Path(__file__).resolve().parents[1]))  # src/ 를 import 경로에 추가
from ai.detector import detector  # noqa: E402

# telemetry 실제 컬럼: cpu_usage, ram_usage, traffic_in_mbps, packet_loss (ping 없음 → 항상 0)
CANDIDATES = {
    "cpu": ("cpu_usage", "cpu"),
    "ram": ("ram_usage", "ram"),
    "traffic": ("traffic_in_mbps", "traffic_in", "traffic"),
    "ping": ("ping", "latency", "latency_ms"),
    "loss": ("packet_loss", "loss"),
}
def train_query():
    """학습에 쓸 텔레메트리 조회. AI_TRAIN_DEVICE_ID가 있으면 그 장비만, 없으면 전체."""
    dev = os.getenv("AI_TRAIN_DEVICE_ID", "").strip()
    if dev.isdigit():
        return (text("SELECT * FROM telemetry WHERE device_id = :d ORDER BY id DESC LIMIT 5000"),
                {"d": int(dev)})
    return text("SELECT * FROM telemetry ORDER BY id DESC LIMIT 5000"), {}
SUSPECT_TTL = 60  # 초. 이보다 오래된 의심 프로세스 보고는 무시


def _int_env(name: str, default: int, minimum: int = 1) -> int:
    """숫자 환경변수. 비어 있거나 숫자가 아니면 기본값을 쓰고 로그에 경고를 남긴다."""
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return max(minimum, int(raw.strip()))
    except ValueError:
        print(f"[config] 경고: {name}={raw!r} 는 숫자가 아니라서 기본값 {default} 을(를) 사용합니다")
        return default


# 한 번 튀는 값으로 경보가 뜨지 않도록, 같은 장비의 최신 측정값이 이 횟수만큼 연속으로 이상일 때만 경보를 만든다.
# (1 = 바로 경보, 기본 2). 폰에서 누르는 시연용 장애는 sim_routes 가 경보를 직접 만들므로 이 값의 영향을 받지 않는다.
AI_CONFIRM_COUNT = _int_env("AI_CONFIRM_COUNT", 2)
print(f"[config] AI 이상 감지: 최신 측정값 {AI_CONFIRM_COUNT}회 연속 이상일 때 경보")

_lock = threading.Lock()
_commands: dict[int, list[dict]] = {}  # device_id -> 대기 중 명령 (서버 재시작 시 초기화)
_suspects: dict[int, dict] = {}        # device_id -> 에이전트가 보고한 의심 프로세스
_pending: dict[str, dict] = {}         # client_uuid -> 미등록 기기
_conn_reqs: dict[int, dict] = {}   # 승인자(기기) device_id -> 연결 요청
_conn_done: list[dict] = []        # 관리자에게 알릴 처리 결과

class HeartbeatReq(BaseModel):
    ok: bool
    rtt_ms: float | None = None


class RestoreReq(BaseModel):
    confirm: str
    data: dict


class ConnReq(BaseModel):
    source_id: int
    target_id: int


class ConnResp(BaseModel):
    request_id: str
    accept: bool


ALLOWED_TYPES = {"router", "switch", "server", "app", "pc", "mobile", "firewall", "printer", "access-point"}
_last_req: dict[str, float] = {}
_last_hb: dict[str, float] = {}


def _clean_name(s: str) -> str:
    """팝업 HTML에 들어가므로 위험 문자를 제거한다."""
    return re.sub(r'[<>"\'&`\\]', "", s or "").strip()[:50]


_UUID_RE = re.compile(r"^[A-Za-z0-9-]{8,64}$")


def _client_uuid(request: Request, required: bool = True) -> str:
    """브라우저가 보내는 X-Device-Id 헤더. 같은 공인 IP여도 기기마다 다르다."""
    cid = (request.headers.get("x-device-id") or "").strip()
    if not _UUID_RE.match(cid):
        if required:
            raise HTTPException(status_code=400, detail="기기 식별자가 없습니다. 페이지를 새로고침해 주세요")
        return ""
    return cid


def _client_ip(request: Request) -> str:
    """프록시(Render) 뒤에서는 X-Forwarded-For 의 첫 번째 값을 쓴다. 표시용 정보일 뿐 식별에는 쓰지 않는다."""
    fwd = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    raw = fwd or (request.client.host if request.client else "")
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return "0.0.0.0"


class SelfRegisterReq(BaseModel):
    name: str
    type: str = "mobile"

def _pick(row: dict, names: tuple) -> float:
    for n in names:
        if row.get(n) is not None:
            try:
                return float(row[n])
            except (TypeError, ValueError):
                pass
    return 0.0


def to_features(row: dict) -> dict:
    return {k: _pick(row, v) for k, v in CANDIDATES.items()}


def _json(v):
    return json.loads(v) if isinstance(v, (str, bytes)) else (v or {})

_alerts_scoped = None        # alerts 테이블에 device_id 칸이 있으면 True (계정별 경보 필터용)
_alerts_scope_retry = 0.0    # 준비에 실패하면 이 시각 이후에 다시 시도
_scope_lock = threading.Lock()


def ensure_alert_scope(db) -> bool:
    """alerts 테이블에 device_id 칸이 있는지 확인하고, 없으면 추가한다. 성공하면 True.
    DDL(ALTER)은 진행 중인 트랜잭션을 확정시키므로, 서버 시작 때와 경보 '조회' 때만 호출한다(add_alert 안에서는 호출하지 않는다)."""
    global _alerts_scoped, _alerts_scope_retry
    if _alerts_scoped:
        return True
    now = time.time()
    if now < _alerts_scope_retry:
        return False
    with _scope_lock:
        if _alerts_scoped:
            return True
        try:
            has = db.execute(text(
                "SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() "
                "AND TABLE_NAME = 'alerts' AND COLUMN_NAME = 'device_id' LIMIT 1")).first()
            if not has:
                db.execute(text("ALTER TABLE alerts ADD COLUMN device_id INT NULL, ADD INDEX idx_alerts_device (device_id)"))
                db.commit()
            _alerts_scoped = True
        except Exception as e:
            try:
                db.rollback()
            except Exception:
                pass
            _alerts_scope_retry = now + 60
            print(f"[config] 경고: 경보 계정별 필터 준비 실패(1분 뒤 다시 시도): {e}")
        return bool(_alerts_scoped)


def add_alert(db, lv, title, msg, cause="", action="", device_id=None):
    """보안 로그(alerts)에 한 줄 남긴다. commit은 호출한 쪽에서 한다.
    device_id 는 경보가 가리키는 장비. 일반 사용자는 '본인 소유 장비'의 경보만 볼 수 있으므로 장비가 있는 경보에는 꼭 넣는다."""
    if _alerts_scoped:
        db.execute(text("INSERT INTO alerts (lv, title, msg, cause, action, device_id) VALUES (:lv,:t,:m,:c,:a,:d)"),
                   {"lv": lv, "t": title[:190], "m": msg, "c": cause[:490], "a": action[:490], "d": device_id})
    else:
        db.execute(text("INSERT INTO alerts (lv, title, msg, cause, action) VALUES (:lv,:t,:m,:c,:a)"),
                   {"lv": lv, "t": title[:190], "m": msg, "c": cause[:490], "a": action[:490]})

def visible_device_ids(db, user):
    """admin이면 None(전체), 일반 사용자는 본인(owner_id)이 연결한 장비 id 집합."""
    if user.get("role") == "admin":
        return None
    rows = db.execute(text("SELECT d.id FROM devices d WHERE d.owner_id = :u"),
                      {"u": user["user_id"]}).fetchall()
    return {x.id for x in rows}


INCIDENT_ACTION_LABEL = {"open": "미조치", "mitigated": "완화", "blocked": "차단"}
BACKUP_LABEL = {"ok": "성공", "partial": "일부 실패", "failed": "실패", "skipped": "미실행"}
_INCIDENT_BLOCK_NAMES = {"backdoor.exe", "mimikatz.exe", "ransomware.exe", "psexec.exe", "nc.exe"}
_incident_ready = {"ok": False}


def recommend_action(process_name: str) -> dict:
    """사고 유형에 따른 권장 조치. 악성 도구로 알려진 이름이면 차단, 그 밖이면 완화."""
    if (process_name or "").lower() in _INCIDENT_BLOCK_NAMES:
        return {"level": "차단", "text": "의심 프로세스를 종료하고 네트워크 연결을 차단하세요. "
                                         "종료 후 백업 파일로 설정과 로그를 확인하세요."}
    return {"level": "완화", "text": "해당 PC의 감시를 강화하고 로그를 확인하세요. "
                                     "설정 변경이 있었다면 백업 파일과 비교해 복구를 검토하세요."}


def ensure_incident_tables(db):
    """사고 보고 관련 테이블과 칸을 준비한다. 한 번 성공하면 다시 확인하지 않는다."""
    if _incident_ready["ok"]:
        return
    db.execute(text(
        "CREATE TABLE IF NOT EXISTS incident_reports ("
        " id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,"
        " device_id INT NULL,"
        " device_name VARCHAR(100) NOT NULL DEFAULT '',"
        " device_ip VARCHAR(45) NOT NULL DEFAULT '',"
        " process_name VARCHAR(255) NOT NULL DEFAULT '',"
        " pid INT NULL,"
        " incident_type VARCHAR(50) NOT NULL DEFAULT '악성 의심 프로세스',"
        " cause VARCHAR(500) NOT NULL DEFAULT '',"
        " occurred_at DATETIME(3) NULL,"
        " backup_status VARCHAR(10) NOT NULL DEFAULT 'skipped',"
        " backup_path VARCHAR(500) NOT NULL DEFAULT '',"
        " backup_detail TEXT NULL,"
        " action_status VARCHAR(20) NOT NULL DEFAULT 'open',"
        " created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),"
        " INDEX idx_ir_device (device_id)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"))
    db.execute(text(
        "CREATE TABLE IF NOT EXISTS incident_actions ("
        " id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,"
        " incident_id INT NOT NULL,"
        " action VARCHAR(20) NOT NULL,"
        " actor VARCHAR(50) NOT NULL DEFAULT '',"
        " note VARCHAR(255) NOT NULL DEFAULT '',"
        " created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),"
        " INDEX idx_ia_incident (incident_id)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"))
    db.execute(text(
        "CREATE TABLE IF NOT EXISTS app_settings ("
        " k VARCHAR(50) NOT NULL PRIMARY KEY,"
        " v VARCHAR(200) NOT NULL"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"))
    db.execute(text("INSERT IGNORE INTO app_settings (k, v) VALUES ('incident_retain_days', '30')"))
    # 보고함 기능용 칸 (이미 만든 테이블에는 빠져 있으므로 없을 때만 추가)
    for col, ddl in (("read_at", "ADD COLUMN read_at DATETIME(3) NULL"),
                     ("later_until", "ADD COLUMN later_until DATETIME(3) NULL"),
                     ("held", "ADD COLUMN held TINYINT NOT NULL DEFAULT 0"),
                     ("ai_incident_id", "ADD COLUMN ai_incident_id INT NULL")):
        has = db.execute(text(
            "SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() "
            "AND TABLE_NAME = 'incident_reports' AND COLUMN_NAME = :c LIMIT 1"), {"c": col}).first()
        if not has:
            db.execute(text(f"ALTER TABLE incident_reports {ddl}"))
    db.commit()
    _incident_ready["ok"] = True


def _retain_days(db) -> int:
    """보고 보관 기간(일). 0이면 영구 보관."""
    row = db.execute(text("SELECT v FROM app_settings WHERE k = 'incident_retain_days'")).first()
    try:
        return max(0, int(row.v)) if row else 30
    except (TypeError, ValueError):
        return 30


class LaterReq(BaseModel):
    minutes: int = Field(default=10, ge=1, le=1440)


class RetainReq(BaseModel):
    days: int = Field(default=30, ge=0, le=3650)   # 0 = 영구 보관


BACKUP_MAX_BYTES = 5 * 1024 * 1024          # 장비 하나의 백업 최대 크기
BACKUP_KEEP = 5                              # 장비당 보관 개수
BACKUP_INTERVAL_SEC = 12 * 3600              # 자동 백업 주기 (12시간)
_backup_ready = {"ok": False}
_backup_sched = {"started": False}


class BackupIn(BaseModel):
    device_id: int
    name: str = Field(default="backup.zip", max_length=200)
    data_b64: str = Field(min_length=1, max_length=8_000_000)


def ensure_backup_table(db):
    """장비 백업 테이블을 만든다. 한 번 성공하면 다시 확인하지 않는다."""
    if _backup_ready["ok"]:
        return
    db.execute(text(
        "CREATE TABLE IF NOT EXISTS device_backups ("
        " id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,"
        " device_id INT NOT NULL,"
        " kind VARCHAR(10) NOT NULL,"
        " name VARCHAR(200) NOT NULL,"
        " size INT NOT NULL DEFAULT 0,"
        " created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),"
        " data MEDIUMBLOB NOT NULL,"
        " INDEX idx_bk_dev (device_id, id)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"))
    db.commit()
    _backup_ready["ok"] = True


def store_backup(db, device_id, kind, name, data: bytes):
    """백업을 저장하고, 이 장비의 오래된 백업은 BACKUP_KEEP개만 남기고 지운다."""
    ensure_backup_table(db)
    if len(data) > BACKUP_MAX_BYTES:
        raise ValueError("백업이 5MB를 넘어 서버에 저장하지 않았어요")
    db.execute(text("INSERT INTO device_backups (device_id, kind, name, size, data) "
                    "VALUES (:d, :k, :n, :s, :b)"),
               {"d": device_id, "k": kind, "n": name[:200], "s": len(data), "b": data})
    db.execute(text(
        "DELETE FROM device_backups WHERE device_id = :d AND id NOT IN ("
        f" SELECT id FROM (SELECT id FROM device_backups WHERE device_id = :d ORDER BY id DESC LIMIT {BACKUP_KEEP}) t)"),
        {"d": device_id})
    db.commit()


def make_config_snapshot(db, device_id) -> bytes:
    """폰·아이패드용 설정 스냅샷(JSON). 기기 안의 파일은 포함하지 않는다."""
    dev = db.execute(text(
        "SELECT d.id, d.name, d.ip, d.type, d.x, d.y, d.vlan_id, u.username AS owner "
        "FROM devices d LEFT JOIN users u ON u.id = d.owner_id WHERE d.id = :d"), {"d": device_id}).first()
    if not dev:
        return b""
    links = [dict(x._mapping) for x in db.execute(text(
        "SELECT source_id, target_id FROM links WHERE source_id = :d OR target_id = :d"), {"d": device_id}).fetchall()]
    try:
        incs = [{"created_at": str(x.created_at), "type": x.incident_type, "cause": x.cause,
                 "action": x.action_status} for x in db.execute(text(
                     "SELECT created_at, incident_type, cause, action_status FROM incident_reports "
                     "WHERE device_id = :d ORDER BY id DESC LIMIT 20"), {"d": device_id}).fetchall()]
    except Exception:
        incs = []
    snap = {"snapshot_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "device": {"id": dev.id, "name": dev.name, "ip": dev.ip, "type": dev.type, "owner": dev.owner,
                       "vlan_id": dev.vlan_id, "x": dev.x, "y": dev.y},
            "links": links, "incident_reports": incs}
    return json.dumps(snap, ensure_ascii=False, indent=2, default=str).encode("utf-8")


def _backup_tick(get_db):
    """12시간마다 폰·아이패드 설정 스냅샷을 저장한다. PC 파일 백업은 에이전트가 한다."""
    gen = get_db()
    db = next(gen)
    try:
        ensure_backup_table(db)
        for d in db.execute(text("SELECT id, type FROM devices")).fetchall():
            if d.type == "pc":
                continue
            age = db.execute(text(
                "SELECT TIMESTAMPDIFF(SECOND, created_at, NOW(3)) AS age FROM device_backups "
                "WHERE device_id = :d ORDER BY id DESC LIMIT 1"), {"d": d.id}).scalar()
            if age is None or age >= BACKUP_INTERVAL_SEC:
                store_backup(db, d.id, "config", f"설정 자동 {datetime.now():%Y%m%d_%H%M}.json",
                             make_config_snapshot(db, d.id))
    except Exception as e:
        print(f"[backup] 자동 설정 백업 오류: {e}")
    finally:
        try:
            gen.close()
        except Exception:
            pass


def start_backup_scheduler(get_db):
    """서버 안에서 10분마다 주기를 확인하는 백그라운드 작업을 한 번만 켠다."""
    if _backup_sched["started"]:
        return
    _backup_sched["started"] = True

    def loop():
        while True:
            time.sleep(600)
            _backup_tick(get_db)

    threading.Thread(target=loop, daemon=True).start()


class IncidentBackup(BaseModel):
    status: str = "skipped"          # ok / partial / failed / skipped
    path: str = ""
    files: list[dict] = Field(default_factory=list)


class IncidentIn(BaseModel):
    device_id: int
    ip: str = ""
    hostname: str = ""
    process_name: str
    pid: int | None = None
    cause: str = ""
    occurred_at: str = ""            # 에이전트 PC의 현재 시각 "YYYY-MM-DD HH:MM:SS"
    backup: IncidentBackup = Field(default_factory=IncidentBackup)


class IncidentActionReq(BaseModel):
    action: Literal["open", "mitigated", "blocked"]
    note: str = Field(default="", max_length=200)


class BlockReq(BaseModel):
    incident_id: int
    mode: Literal["kill", "firewall"] = "kill"


class FeedbackReq(BaseModel):
    incident_id: int


class HelloReq(BaseModel):
    ip: str
    hostname: str = ""


class SuspectReq(BaseModel):
    device_id: int
    pid: int
    name: str
    create_time: float
    exe: str = ""


class CmdResult(BaseModel):
    ok: bool
    detail: str = ""


class EnrollReq(BaseModel):
    ip: str
    client_uuid: str = ""  # 브라우저 기기는 UUID, 로컬 agent PC는 비움
    name: str
    type: str = "pc"
    vlan_code: str


def score_rows(db, rows: list[dict]) -> list[dict]:
    """telemetry 행들에 risk_score를 붙이고, 이상이면 경보(ai_incidents)와 보안 로그(alerts)를 만든다.
    main.py의 /api/telemetry/latest 에서 호출.
    경보는 장비의 최신 측정값이 AI_CONFIRM_COUNT 회 연속 이상일 때만 만든다(한 번 튀는 값은 무시)."""
    if not detector.trained:
        train = [to_features(dict(x._mapping)) for x in db.execute(*train_query())]
        if len(train) >= 50:
            detector.train_baseline(train)

    per_dev: dict = {}   # device_id -> [판정 결과, ...] (rows는 id DESC 이므로 앞쪽이 최신)
    feats_latest: dict = {}
    for row in rows:
        feats = to_features(row)
        res = detector.predict_risk(feats)
        row["risk_score"], row["is_anomaly"] = res["risk_score"], res["is_anomaly"]
        dev = row.get("device_id")
        if dev is None:
            continue
        per_dev.setdefault(dev, []).append(res)
        feats_latest.setdefault(dev, feats)

    if not detector.trained:
        return rows  # 미학습 상태에서는 경보를 만들지 않는다

    for dev, results in per_dev.items():
        res = results[0]
        if not res["is_anomaly"]:
            continue
        need = AI_CONFIRM_COUNT
        if len(results) < need or not all(x["is_anomaly"] for x in results[:need]):
            continue  # 최신 측정값이 연속으로 이상일 때만 (한 번 튀는 값은 무시)
        if db.execute(text("SELECT 1 FROM ai_incidents WHERE device_id=:d AND status IN ('open','block_pending') LIMIT 1"),
                      {"d": dev}).first():
            continue  # 이미 열린 경보가 있으면 새로 만들지 않는다 (중복·도배 방지)
        feats = feats_latest[dev]
        s = _suspects.get(dev)
        if s and time.time() - s["ts"] > SUSPECT_TTL:
            s = None
        msg = (f"의심 프로세스 {s['name']}(PID {s['pid']}) 감지! 차단하시겠습니까?" if s
               else f"장비 #{dev}: {res['top_factor'] or '이상'} 이상 징후 감지")
        db.execute(text(
            "INSERT INTO ai_incidents (device_id, risk_score, message, process_name, pid, proc_create_time, features) "
            "VALUES (:d,:r,:m,:pn,:pid,:ct,:f)"),
            {"d": dev, "r": res["risk_score"], "m": msg, "pn": s and s["name"], "pid": s and s["pid"],
             "ct": s and s["create_time"], "f": json.dumps(feats)})
        add_alert(db, "crit", "🤖 AI 이상 감지", msg,
                  f"위험도 {res['risk_score']}% · 주요 요인: {res['top_factor'] or '-'}",
                  "승인/차단 또는 오탐/재학습을 선택하세요", device_id=dev)
        db.commit()
    # 열린 경보가 있는 장비의 최신 측정값이 AI_CONFIRM_COUNT 회 연속 정상이면 경보를 자동으로 닫는다
    for dev, results in per_dev.items():
        if len(results) < AI_CONFIRM_COUNT or any(x["is_anomaly"] for x in results[:AI_CONFIRM_COUNT]):
            continue
        res_upd = db.execute(text("UPDATE ai_incidents SET status='auto_resolved' WHERE device_id=:d AND status='open'"),
                             {"d": dev})
        if res_upd.rowcount:
            dname = db.execute(text("SELECT name FROM devices WHERE id=:d"), {"d": dev}).first()
            add_alert(db, "info", "✅ 정상 복귀", f"{(dname[0] if dname else '장비 #' + str(dev))}: 측정값이 정상 범위로 돌아와 경보를 자동으로 닫았어요",
                      "연속 측정 정상", "별도 조치 불필요", device_id=dev)
            db.commit()
    return rows


KST = timezone(timedelta(hours=9))          # 한국 시간 고정 (+09:00, 서머타임 없음)
DEFAULT_SHIFTS = [{"name": "주간", "start": "06:00"}, {"name": "저녁", "start": "14:00"}, {"name": "야간", "start": "22:00"}]


_SIM = {"on": False, "speed": 1, "real0": None, "sim0": None}   # 전시용 시뮬레이션 시계


def _kst_now():
    """교대 판정과 인수인계 기록에 쓰는 현재 시각. 시뮬레이션이 켜져 있으면 빠르게 흐른 시각."""
    real = datetime.now(KST).replace(tzinfo=None)
    if _SIM["on"] and _SIM["real0"] and _SIM["sim0"]:
        elapsed = (real - _SIM["real0"]).total_seconds()
        return _SIM["sim0"] + timedelta(seconds=elapsed * _SIM["speed"])
    return real


def _sim_save(db):
    _setting_set(db, "shift_sim", json.dumps({
        "on": _SIM["on"], "speed": _SIM["speed"],
        "real0": _SIM["real0"].isoformat() if _SIM["real0"] else None,
        "sim0": _SIM["sim0"].isoformat() if _SIM["sim0"] else None}))
    db.commit()


def _sim_load(db):
    raw_ = _setting_get(db, "shift_sim")
    try:
        d = json.loads(raw_) if raw_ else None
    except (TypeError, ValueError):
        d = None
    if not d:
        return
    _SIM["on"] = bool(d.get("on"))
    _SIM["speed"] = int(d.get("speed") or 1)
    _SIM["real0"] = datetime.fromisoformat(d["real0"]) if d.get("real0") else None
    _SIM["sim0"] = datetime.fromisoformat(d["sim0"]) if d.get("sim0") else None


def _next_shift_start(shifts, now):
    """현재 시각 다음에 오는 교대 시작 시각."""
    starts = sorted(_hm_minutes(s["start"]) for s in shifts)
    t_now = now.hour * 60 + now.minute
    for m in starts:
        if m > t_now:
            return datetime.combine(now.date(), _tm(m // 60, m % 60))
    m = starts[0]
    return datetime.combine(now.date() + timedelta(days=1), _tm(m // 60, m % 60))


def _setting_get(db, key, default=None):
    row = db.execute(text("SELECT v FROM app_settings WHERE k = :k"), {"k": key}).first()
    return row[0] if row else default


def _setting_set(db, key, value):
    db.execute(text("INSERT INTO app_settings (k, v) VALUES (:k, :v) ON DUPLICATE KEY UPDATE v = VALUES(v)"),
               {"k": key, "v": value})


def _load_plan(db):
    raw = _setting_get(db, "shift_plan")
    try:
        shifts = json.loads(raw) if raw else None
    except (TypeError, ValueError):
        shifts = None
    return shifts or [dict(s) for s in DEFAULT_SHIFTS]


def _hm_minutes(s):
    hh, mm = str(s).split(":")
    return int(hh) * 60 + int(mm)


def _current_shift(shifts, now):
    """지금 몇 교대인지 돌려준다: (교대 키, 교대 이름, 교대 시작 시각)."""
    order = sorted((_hm_minutes(s["start"]), i) for i, s in enumerate(shifts))
    t_now = now.hour * 60 + now.minute
    cur = None
    for start, i in order:
        if start <= t_now:
            cur = (start, i, now.date())
    if cur is None:                          # 첫 교대 시작 전이면 전날의 마지막 교대
        start, i = order[-1]
        cur = (start, i, now.date() - timedelta(days=1))
    start, i, d = cur
    start_at = datetime.combine(d, _tm(start // 60, start % 60))
    return f"{d.isoformat()}|{i}", shifts[i]["name"], start_at


def _shift_tables(db):
    """근무 관련 테이블을 한 번만 만든다 (이미 있으면 그대로 둔다)."""
    if _shift_ready["ok"]:
        return
    ensure_incident_tables(db)
    db.execute(text("""CREATE TABLE IF NOT EXISTS handover_reports (
        id INT AUTO_INCREMENT PRIMARY KEY,
        shift_date DATE NOT NULL,
        shift_name VARCHAR(20) NOT NULL,
        author_name VARCHAR(50) NOT NULL,
        summary VARCHAR(255) NOT NULL DEFAULT '',
        body TEXT NOT NULL,
        snapshot TEXT NULL,
        created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"""))
    db.execute(text("""CREATE TABLE IF NOT EXISTS notices (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(200) NOT NULL,
        body TEXT NOT NULL,
        author_name VARCHAR(50) NOT NULL,
        pinned TINYINT NOT NULL DEFAULT 0,
        created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"""))
    db.execute(text("""CREATE TABLE IF NOT EXISTS notice_reads (
        notice_id INT NOT NULL,
        user_id INT NOT NULL,
        read_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
        PRIMARY KEY (notice_id, user_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"""))
    db.execute(text("""CREATE TABLE IF NOT EXISTS notice_targets (
        notice_id INT NOT NULL,
        device_id INT NOT NULL,
        PRIMARY KEY (notice_id, device_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"""))
    db.execute(text("""CREATE TABLE IF NOT EXISTS staff_memos (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        body TEXT NOT NULL,
        created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
        updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
        INDEX idx_memo_user (user_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"""))
    db.execute(text("""CREATE TABLE IF NOT EXISTS shift_reports (
        id INT AUTO_INCREMENT PRIMARY KEY,
        report_key VARCHAR(40) NOT NULL UNIQUE,
        shift_name VARCHAR(20) NOT NULL,
        shift_date DATE NOT NULL,
        start_at DATETIME(3) NOT NULL,
        end_at DATETIME(3) NOT NULL,
        summary TEXT NOT NULL,
        created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"""))
    db.execute(text("""CREATE TABLE IF NOT EXISTS shift_deliveries (
        id INT AUTO_INCREMENT PRIMARY KEY,
        report_id INT NOT NULL,
        user_id INT NOT NULL,
        snapshot TEXT NULL,
        delivered_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
        read_at DATETIME(3) NULL,
        UNIQUE KEY uq_delivery (report_id, user_id),
        INDEX idx_delivery_user (user_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"""))
    db.commit()
    _shift_ready["ok"] = True


_shift_ready = {"ok": False}


# 사용자에게 보이는 공지: 대상 지정이 없는 공지(예전 공지)·전체 공지·내 장비 담당 공지
NOTICE_VISIBLE_USER = (
    "(NOT EXISTS (SELECT 1 FROM notice_targets t0 WHERE t0.notice_id = n.id) "
    "OR n.id IN (SELECT t1.notice_id FROM notice_targets t1 WHERE t1.device_id = 0) "
    "OR n.id IN (SELECT t2.notice_id FROM notice_targets t2 JOIN devices d ON d.id = t2.device_id "
    "WHERE d.owner_id = :u))"
)


def _notice_targets(db, nid):
    rows = [int(x[0]) for x in db.execute(text(
        "SELECT device_id FROM notice_targets WHERE notice_id = :n"), {"n": nid}).fetchall()]
    if not rows or 0 in rows:
        return {"all": True, "devices": []}
    return {"all": False, "devices": rows}


def _notice_recipient_ids(db, nid):
    t_ = _notice_targets(db, nid)
    if t_["all"]:
        return {int(x[0]) for x in db.execute(text("SELECT id FROM users WHERE role <> 'admin'")).fetchall()}
    rows = db.execute(text(
        "SELECT DISTINCT owner_id FROM devices WHERE id IN :ids AND owner_id IS NOT NULL"
    ).bindparams(bindparam("ids", expanding=True)), {"ids": t_["devices"]}).fetchall()
    return {int(x[0]) for x in rows}


class HandoverIn(BaseModel):
    shift_name: str = Field(default="주간", max_length=20)
    summary: str = Field(default="", max_length=255)
    body: str = Field(..., min_length=1, max_length=5000)


class NoticeIn(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    body: str = Field(..., min_length=1, max_length=5000)
    pinned: int = Field(default=0)
    all_users: bool = Field(default=True)
    device_ids: list = Field(default_factory=list)


class MemoIn(BaseModel):
    body: str = Field(..., min_length=1, max_length=5000)


class SimIn(BaseModel):
    on: bool = Field(default=False)
    speed: int = Field(default=60)
    start: str = Field(default="")


class ShiftPlanIn(BaseModel):
    shifts: list = Field(default_factory=list)


class AlertRetainReq(BaseModel):
    days: int = Field(default=30)


def build_ai_router(get_db, get_current_user, require_admin, agent_key: str) -> APIRouter:
    r = APIRouter()

    def agent_auth(x_api_key: str = Header(default="")):
        if not x_api_key or not hmac.compare_digest(x_api_key, agent_key):
            raise HTTPException(status_code=403, detail="Invalid API Key")

    # ---------- 경보 조회 / 재학습 ----------
    @r.get("/api/ai/incidents")
    def incidents(db=Depends(get_db), user=Depends(get_current_user)):
        rows = db.execute(text(
            "SELECT id, device_id, risk_score, message, status, process_name, pid, created_at "
            "FROM ai_incidents WHERE status IN ('open','block_pending') ORDER BY id DESC LIMIT 20")).fetchall()
        ids = visible_device_ids(db, user)
        items = [dict(x._mapping) for x in rows]
        if ids is not None:
            items = [x for x in items if x["device_id"] in ids]
        return {"can_act": user.get("role") == "admin", "incidents": items, "model_trained": detector.trained}

    @r.post("/api/ai/train")
    def retrain(db=Depends(get_db), user=Depends(require_admin)):
        rows = [to_features(dict(x._mapping)) for x in db.execute(*train_query())]
        try:
            return {"trained_samples": detector.train_baseline(rows)}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    # ---------- 관리자 승인 차단 ----------
    @r.post("/api/security/block")
    def approve_block(req: BlockReq, db=Depends(get_db), user=Depends(require_admin)):
        a = db.execute(text("SELECT * FROM ai_incidents WHERE id=:i"), {"i": req.incident_id}).first()
        if not a:
            raise HTTPException(status_code=404, detail="경보를 찾을 수 없습니다")
        a = dict(a._mapping)
        if a["status"] != "open":
            raise HTTPException(status_code=409, detail="이미 처리된 경보입니다")
        if not a["pid"]:
            raise HTTPException(status_code=400, detail="차단할 프로세스 정보가 없습니다")
        cmd = {"id": uuid.uuid4().hex, "incident_id": a["id"], "mode": req.mode,
               "pid": a["pid"], "name": a["process_name"], "create_time": a["proc_create_time"]}
        with _lock:
            _commands.setdefault(a["device_id"], []).append(cmd)
        db.execute(text("UPDATE ai_incidents SET status='block_pending' WHERE id=:i"), {"i": a["id"]})
        add_alert(db, "warn", "🛡 차단 승인", f"관리자가 '{a['process_name']}'(PID {a['pid']}) 차단을 승인했습니다",
                  "관리자 승인", "에이전트가 프로세스를 종료합니다", device_id=a["device_id"])
        db.commit()
        return {"command_id": cmd["id"], "status": "block_pending"}

    # ---------- 오탐 피드백 (재학습) ----------
    @r.post("/api/ai/feedback")
    def feedback(req: FeedbackReq, db=Depends(get_db), user=Depends(require_admin)):
        a = db.execute(text("SELECT features, device_id FROM ai_incidents WHERE id=:i"), {"i": req.incident_id}).first()
        if not a or not a.features:
            raise HTTPException(status_code=404, detail="경보 또는 특징 데이터가 없습니다")
        feats = _json(a.features)
        before = detector.predict_risk(feats)["risk_score"]
        try:
            total = detector.add_feedback(feats)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        
        after = detector.predict_risk(feats)["risk_score"]
        add_alert(db, "info", "♻ 오탐 재학습", f"위험도 {before}% → {after}%", "관리자가 오탐으로 판정", "정상 기준선에 반영됨", device_id=a.device_id)
        db.execute(text("UPDATE ai_incidents SET status='false_positive' WHERE id=:i"), {"i": req.incident_id})
        db.commit()
        return {"risk_before": before, "risk_after": detector.predict_risk(feats)["risk_score"], "baseline_size": total}

    # ---------- 에이전트 전용 ----------
    @r.post("/api/agent/hello", dependencies=[Depends(agent_auth)])
    def hello(req: HelloReq, db=Depends(get_db)):
        row = db.execute(text("SELECT id FROM devices WHERE ip=:ip"), {"ip": req.ip}).first()
        if row:
            _pending.pop(req.ip, None)
            return {"registered": True, "device_id": row.id}
        cur = _pending.get(req.ip)
        if not (cur and cur.get("requested")):  # 사용자가 직접 입력한 이름을 스캐너가 덮어쓰지 않게
            _pending[req.ip] = {"ip": req.ip, "hostname": _clean_name(req.hostname)}
        return {"registered": False}

    @r.post("/api/agent/suspect", dependencies=[Depends(agent_auth)])
    def suspect(req: SuspectReq):
        _suspects[req.device_id] = {**req.model_dump(), "ts": time.time()}
        return {"ok": True}

    @r.get("/api/agent/commands", dependencies=[Depends(agent_auth)])
    def poll_commands(device_id: int):
        with _lock:
            return {"commands": _commands.pop(device_id, [])}

    @r.post("/api/agent/commands/{cmd_id}/result", dependencies=[Depends(agent_auth)])
    def cmd_result(cmd_id: str, res: CmdResult, incident_id: int, db=Depends(get_db)):
        status = "blocked" if res.ok else "block_failed"
        db.execute(text("UPDATE ai_incidents SET status=:s WHERE id=:i"), {"s": status, "i": incident_id})
        inc = db.execute(text("SELECT device_id FROM ai_incidents WHERE id=:i"), {"i": incident_id}).first()
        add_alert(db, "info" if res.ok else "crit", "차단 완료" if res.ok else "차단 실패", res.detail, "에이전트 실행 결과", device_id=inc.device_id if inc else None)
        db.commit()
        return {"status": status, "detail": res.detail}

        # ---------- 사고 보고서 (에이전트 자동 백업 결과 + 관리자 조치 이력) ----------
    def _incident_tables(db):
        ensure_incident_tables(db)

    @r.post("/api/agent/incident", dependencies=[Depends(agent_auth)])
    def agent_incident(req: IncidentIn, db=Depends(get_db)):
        """에이전트가 보낸 사고 보고를 저장하고 관리자 보안 로그에 한 줄 남긴다."""
        _incident_tables(db)
        dev = db.execute(text(
            "SELECT d.id, d.name, d.ip, u.username AS owner FROM devices d "
            "LEFT JOIN users u ON u.id = d.owner_id WHERE d.id = :d"), {"d": req.device_id}).first()
        if not dev:
            raise HTTPException(status_code=404, detail="등록되지 않은 장비입니다")
        try:
            occurred = datetime.strptime(req.occurred_at, "%Y-%m-%d %H:%M:%S") if req.occurred_at else None
        except ValueError:
            occurred = None
        bstatus = req.backup.status if req.backup.status in BACKUP_LABEL else "skipped"
        res = db.execute(text(
            "INSERT INTO incident_reports (device_id, device_name, device_ip, process_name, pid, cause, "
            "occurred_at, backup_status, backup_path, backup_detail) "
            "VALUES (:d, :n, :ip, :p, :pid, :c, :o, :bs, :bp, :bd)"),
            {"d": dev.id, "n": (dev.name or "")[:100], "ip": (dev.ip or req.ip or "")[:45],
             "p": req.process_name[:255], "pid": req.pid, "c": req.cause[:490], "o": occurred,
             "bs": bstatus, "bp": req.backup.path[:500],
             "bd": json.dumps(req.backup.files, ensure_ascii=False)[:60000]})
        iid = res.lastrowid
        db.execute(text("INSERT INTO incident_actions (incident_id, action, actor, note) "
                        "VALUES (:i, 'open', 'agent', '사고 자동 보고')"), {"i": iid})
        add_alert(db, "crit", f"📋 사고 보고: {req.process_name}",
                  f"{dev.name}({dev.ip}) PID {req.pid} · 백업 {BACKUP_LABEL[bstatus]}",
                  req.cause or "의심 프로세스 감지", "사고 보고서에서 조치를 선택하세요", device_id=dev.id)
        db.commit()
        return {"ok": True, "incident_id": iid}

    @r.get("/api/incidents")
    def list_incidents(db=Depends(get_db), user=Depends(get_current_user)):
        """사고 보고 목록. 관리자는 전체, 일반 사용자는 본인 소유 장비의 보고만."""
        _incident_tables(db)
        rows = db.execute(text(
            "SELECT id, device_id, device_name, process_name, pid, cause, occurred_at, "
            "backup_status, action_status FROM incident_reports ORDER BY id DESC LIMIT 50")).fetchall()
        items = [dict(x._mapping) for x in rows]
        ids = visible_device_ids(db, user)
        if ids is not None:
            items = [x for x in items if x["device_id"] in ids]
        for x in items:
            x["occurred_at"] = str(x["occurred_at"]) if x["occurred_at"] else None
            x["action_label"] = INCIDENT_ACTION_LABEL.get(x["action_status"], x["action_status"])
            x["backup_label"] = BACKUP_LABEL.get(x["backup_status"], x["backup_status"])
        return {"can_act": user.get("role") == "admin", "incidents": items}

    @r.get("/api/incidents/{incident_id}/report")
    def incident_report(incident_id: int, db=Depends(get_db), user=Depends(get_current_user)):
        """사고 발생 보고서 한 건. 관리자 화면에서 경보를 누르면 이 값을 보여 준다."""
        _incident_tables(db)
        row = db.execute(text(
            "SELECT r.*, u.username AS owner FROM incident_reports r "
            "LEFT JOIN devices d ON d.id = r.device_id LEFT JOIN users u ON u.id = d.owner_id "
            "WHERE r.id = :i"), {"i": incident_id}).first()
        if not row:
            raise HTTPException(status_code=404, detail="보고서를 찾을 수 없습니다")
        rep = dict(row._mapping)
        ids = visible_device_ids(db, user)
        if ids is not None and rep["device_id"] not in ids:
            raise HTTPException(status_code=403, detail="이 보고서를 볼 권한이 없습니다")
        hist = db.execute(text(
            "SELECT action, actor, note, created_at FROM incident_actions WHERE incident_id = :i ORDER BY id"),
            {"i": incident_id}).fetchall()
        files = []
        if rep["backup_detail"]:
            try:
                files = json.loads(rep["backup_detail"])
            except Exception:
                files = []
        return {
            "id": rep["id"],
            "occurred_at": str(rep["occurred_at"]) if rep["occurred_at"] else None,
            "reported_at": str(rep["created_at"]),
            "device": {"id": rep["device_id"], "name": rep["device_name"],
                       "ip": rep["device_ip"], "owner": rep["owner"] or "-"},
            "incident": {"type": rep["incident_type"], "cause": rep["cause"],
                         "process_name": rep["process_name"], "pid": rep["pid"]},
            "backup": {"status": rep["backup_status"],
                       "status_label": BACKUP_LABEL.get(rep["backup_status"], "미실행"),
                       "executed": rep["backup_status"] != "skipped",
                       "path": rep["backup_path"], "files": files},
            "recommendation": recommend_action(rep["process_name"]),
            "action_status": rep["action_status"],
            "action_label": INCIDENT_ACTION_LABEL.get(rep["action_status"], rep["action_status"]),
            "history": [{"action": h.action, "label": INCIDENT_ACTION_LABEL.get(h.action, h.action),
                         "actor": h.actor, "note": h.note, "created_at": str(h.created_at)} for h in hist],
        }

    @r.post("/api/incidents/{incident_id}/action")
    def incident_action(incident_id: int, req: IncidentActionReq, db=Depends(get_db),
                        user=Depends(require_admin)):
        """관리자가 조치를 고른다: 미조치 / 완화 / 차단. 기록만 남기며 실제 프로세스 종료는
        기존 '차단 승인' 흐름(/api/security/block)이 담당한다."""
        _incident_tables(db)
        row = db.execute(text("SELECT id FROM incident_reports WHERE id = :i"), {"i": incident_id}).first()
        if not row:
            raise HTTPException(status_code=404, detail="보고서를 찾을 수 없습니다")
        db.execute(text("UPDATE incident_reports SET action_status = :s WHERE id = :i"),
                   {"s": req.action, "i": incident_id})
        db.execute(text("INSERT INTO incident_actions (incident_id, action, actor, note) "
                        "VALUES (:i, :a, :u, :n)"),
                   {"i": incident_id, "a": req.action, "u": str(user.get("username") or "admin")[:50],
                    "n": req.note})
        db.commit()
        return {"ok": True, "action_status": req.action, "label": INCIDENT_ACTION_LABEL[req.action]}

    # ---------- 보고함: 목록·읽음·나중에·보관 기간 ----------
    @r.get("/api/incidents/inbox")
    def incidents_inbox(db=Depends(get_db), user=Depends(get_current_user)):
        _incident_tables(db)
        days = _retain_days(db)
        if days > 0:                                   # 보관 기간이 지난 보고는 지운다
            db.execute(text("DELETE FROM incident_actions WHERE incident_id IN "
                            "(SELECT id FROM incident_reports WHERE created_at < NOW() - INTERVAL :d DAY)"), {"d": days})
            db.execute(text("DELETE FROM incident_reports WHERE created_at < NOW() - INTERVAL :d DAY"), {"d": days})
            db.commit()
        rows = db.execute(text(
            "SELECT id, device_id, device_name, process_name, incident_type, cause, occurred_at, backup_status, "
            "action_status, read_at, later_until, held, created_at, NOW(3) AS now_ts "
            "FROM incident_reports ORDER BY id DESC LIMIT 200")).fetchall()
        items = [dict(x._mapping) for x in rows]
        ids = visible_device_ids(db, user)
        if ids is not None:
            items = [x for x in items if x["device_id"] in ids]
        unread, out = 0, []
        for x in items:
            now_ts = x.pop("now_ts")
            if x["read_at"]:
                state = "read"
            elif x["held"]:
                state = "held"          # 보관만 (알림 없음, 나중에 탭에서 확인)
            elif x["later_until"] and x["later_until"] > now_ts:
                state = "later"
            else:
                state = "unread"
                unread += 1
            out.append({
                "id": x["id"], "device_id": x["device_id"], "device_name": x["device_name"],
                "process_name": x["process_name"], "incident_type": x["incident_type"], "cause": x["cause"],
                "occurred_at": str(x["occurred_at"]) if x["occurred_at"] else None,
                "created_at": str(x["created_at"]), "state": state,
                "later_until": str(x["later_until"]) if x["later_until"] else None,
                "action_status": x["action_status"],
                "action_label": INCIDENT_ACTION_LABEL.get(x["action_status"], x["action_status"]),
            })
        return {"unread": unread, "retain_days": days, "can_admin": user.get("role") == "admin", "incidents": out}

    @r.post("/api/incidents/{incident_id}/read")
    def incident_read(incident_id: int, db=Depends(get_db), user=Depends(get_current_user)):
        _incident_tables(db)
        row = db.execute(text("SELECT device_id FROM incident_reports WHERE id = :i"), {"i": incident_id}).first()
        if not row:
            raise HTTPException(status_code=404, detail="보고서를 찾을 수 없습니다")
        ids = visible_device_ids(db, user)
        if ids is not None and row.device_id not in ids:
            raise HTTPException(status_code=403, detail="이 보고서를 볼 권한이 없습니다")
        db.execute(text("UPDATE incident_reports SET read_at = NOW(3), later_until = NULL, held = 0 WHERE id = :i"),
                   {"i": incident_id})
        db.commit()
        return {"ok": True}

    @r.post("/api/incidents/{incident_id}/later")
    def incident_later(incident_id: int, req: LaterReq, db=Depends(get_db), user=Depends(get_current_user)):
        _incident_tables(db)
        row = db.execute(text("SELECT device_id FROM incident_reports WHERE id = :i"), {"i": incident_id}).first()
        if not row:
            raise HTTPException(status_code=404, detail="보고서를 찾을 수 없습니다")
        ids = visible_device_ids(db, user)
        if ids is not None and row.device_id not in ids:
            raise HTTPException(status_code=403, detail="이 보고서를 볼 권한이 없습니다")
        db.execute(text("UPDATE incident_reports SET read_at = NULL, held = 0, later_until = NOW(3) + INTERVAL :m MINUTE "
                        "WHERE id = :i"), {"m": req.minutes, "i": incident_id})
        db.commit()
        return {"ok": True, "minutes": req.minutes}

    @r.post("/api/incidents/{incident_id}/hold")
    def incident_hold(incident_id: int, db=Depends(get_db), user=Depends(get_current_user)):
        _incident_tables(db)
        row = db.execute(text("SELECT device_id FROM incident_reports WHERE id = :i"), {"i": incident_id}).first()
        if not row:
            raise HTTPException(status_code=404, detail="보고서를 찾을 수 없습니다")
        ids = visible_device_ids(db, user)
        if ids is not None and row.device_id not in ids:
            raise HTTPException(status_code=403, detail="이 보고서를 볼 권한이 없습니다")
        db.execute(text("UPDATE incident_reports SET read_at = NULL, later_until = NULL, held = 1 WHERE id = :i"),
                   {"i": incident_id})
        db.commit()
        return {"ok": True, "state": "held"}

    @r.post("/api/incidents/from-ai/{ai_id}/later")
    def incident_from_ai_later(ai_id: int, req: LaterReq, db=Depends(get_db), user=Depends(get_current_user)):
        """AI 팝업에서 '나중에'를 누른 경보를 보고함에 올려, 나중에 탭에서 다시 찾을 수 있게 한다."""
        _incident_tables(db)
        a = db.execute(text("SELECT * FROM ai_incidents WHERE id = :i"), {"i": ai_id}).first()
        if not a:
            raise HTTPException(status_code=404, detail="경보를 찾을 수 없습니다")
        a = dict(a._mapping)
        ids = visible_device_ids(db, user)
        if ids is not None and a["device_id"] not in ids:
            raise HTTPException(status_code=403, detail="이 경보를 볼 권한이 없습니다")
        rid_row = db.execute(text("SELECT id FROM incident_reports WHERE ai_incident_id = :a LIMIT 1"),
                             {"a": ai_id}).first()
        if rid_row:
            rid = rid_row[0]
        else:
            dev = db.execute(text("SELECT name, ip FROM devices WHERE id = :d"), {"d": a["device_id"]}).first()
            itype = "악성 의심 프로세스" if a.get("pid") else "AI 이상 징후(장애 위험)"
            res = db.execute(text(
                "INSERT INTO incident_reports (device_id, device_name, device_ip, process_name, pid, cause, "
                "occurred_at, backup_status, backup_path, backup_detail, incident_type, ai_incident_id) "
                "VALUES (:d, :n, :ip, :p, :pid, :c, NOW(3), 'skipped', '', NULL, :it, :a)"),
                {"d": a["device_id"], "n": ((dev[0] if dev else "") or "")[:100],
                 "ip": ((dev[1] if dev else "") or "")[:45], "p": (a.get("process_name") or "")[:255],
                 "pid": a.get("pid"), "c": (a.get("message") or "")[:490], "it": itype, "a": ai_id})
            rid = res.lastrowid
        db.execute(text("UPDATE incident_reports SET read_at = NULL, held = 0, "
                        "later_until = NOW(3) + INTERVAL :m MINUTE WHERE id = :i"),
                   {"m": req.minutes, "i": rid})
        db.commit()
        return {"ok": True, "report_id": rid, "minutes": req.minutes}

    # ---------- 보안 로그: 기간별 기록 · 보관 기간 ----------
    def _alert_retain_days(db) -> int:
        row = db.execute(text("SELECT v FROM app_settings WHERE k = 'alert_retain_days'")).first()
        try:
            return int(row[0]) if row else 30
        except (TypeError, ValueError):
            return 30

    @r.get("/api/alerts/history")
    def alerts_history(period: str = "today", lv: str = "all", page: int = 1, size: int = 50,
                       date: str = "", db=Depends(get_db), user=Depends(get_current_user)):
        """보안 로그를 기간·위험도별로 나눠 준다. 관리자=전체, 일반 사용자=본인 장비 경보만."""
        _incident_tables(db)
        days = _alert_retain_days(db)
        if days > 0:                                     # 보관 기간이 지난 알림은 지운다
            db.execute(text("DELETE FROM alerts WHERE `timestamp` < NOW() - INTERVAL :d DAY"), {"d": days})
            db.commit()
        where, params = [], {}
        day_ok = False
        if date:                                         # 달력에서 고른 특정 날짜
            try:
                from datetime import datetime as _dt
                params["dt"] = _dt.strptime(date, "%Y-%m-%d").date()
                where.append("DATE(`timestamp`) = :dt")
                day_ok = True
            except ValueError:
                day_ok = False
        if not day_ok:
            if period == "today":
                where.append("`timestamp` >= DATE(NOW())")
            elif period == "7d":
                where.append("`timestamp` >= NOW() - INTERVAL 7 DAY")
            elif period == "30d":
                where.append("`timestamp` >= NOW() - INTERVAL 30 DAY")
        if lv in ("crit", "warn", "info"):
            where.append("lv = :lv")
            params["lv"] = lv
        ids = None
        if user.get("role") != "admin":
            ids = visible_device_ids(db, user)
            if not ids or not ensure_alert_scope(db):
                return {"items": [], "has_more": False, "retain_days": days, "page": page}
            where.append("device_id IN :ids")
        size = max(1, min(int(size), 200))
        page = max(1, int(page))
        params["lim"] = size + 1
        params["off"] = (page - 1) * size
        sql = ("SELECT id, lv, title, msg, cause, action, `timestamp` AS ts, device_id FROM alerts"
               + (" WHERE " + " AND ".join(where) if where else "")
               + " ORDER BY id DESC LIMIT :lim OFFSET :off")
        q = text(sql)
        if ids is not None:
            q = q.bindparams(bindparam("ids", expanding=True))
            params["ids"] = list(ids)
        rows = [dict(x._mapping) for x in db.execute(q, params).fetchall()]
        has_more = len(rows) > size
        items = []
        for x in rows[:size]:
            items.append({"id": x["id"], "lv": x["lv"], "title": x["title"], "msg": x["msg"],
                          "cause": x["cause"], "action": x["action"],
                          "ts": str(x["ts"]) if x["ts"] else None, "device_id": x["device_id"]})
        return {"items": items, "has_more": has_more, "retain_days": days, "page": page}

    @r.get("/api/alerts/{alert_id}/report")
    def alert_report(alert_id: int, db=Depends(get_db), user=Depends(get_current_user)):
        """알림과 짝이 되는 사고 보고서 번호. 같은 장비에서 5분 안에 만들어진 보고서를 찾는다."""
        _incident_tables(db)
        a = db.execute(text("SELECT device_id, `timestamp` AS ts FROM alerts WHERE id = :i"), {"i": alert_id}).first()
        if not a:
            raise HTTPException(status_code=404, detail="알림을 찾을 수 없어요")
        if a.device_id is None:
            return {"report_id": None}
        if user.get("role") != "admin":
            ids = visible_device_ids(db, user)
            if not ids or a.device_id not in ids:
                raise HTTPException(status_code=403, detail="이 알림을 볼 권한이 없어요")
        rid = db.execute(text(
            "SELECT id FROM incident_reports WHERE device_id = :d "
            "AND ABS(TIMESTAMPDIFF(SECOND, occurred_at, :t)) <= 300 "
            "ORDER BY ABS(TIMESTAMPDIFF(SECOND, occurred_at, :t)) LIMIT 1"),
            {"d": a.device_id, "t": a.ts}).scalar()
        return {"report_id": int(rid) if rid else None}

    @r.get("/api/alerts/calendar")
    def alerts_calendar(month: str = "", db=Depends(get_db), user=Depends(get_current_user)):
        """달력용: 한 달 동안 날짜마다 위험·경고·정보 알림이 몇 건인지 센다."""
        from datetime import date as _date, datetime as _dt
        _incident_tables(db)
        try:
            first = _dt.strptime(month + "-01", "%Y-%m-%d").date()
        except ValueError:
            raise HTTPException(status_code=400, detail="month는 YYYY-MM 형식이어야 해요")
        days_keep = _alert_retain_days(db)
        if days_keep > 0:
            db.execute(text("DELETE FROM alerts WHERE `timestamp` < NOW() - INTERVAL :d DAY"), {"d": days_keep})
            db.commit()
        y, m = (first.year + 1, 1) if first.month == 12 else (first.year, first.month + 1)
        nxt = _date(y, m, 1)
        where = ["`timestamp` >= :s", "`timestamp` < :e"]
        params = {"s": first, "e": nxt}
        ids = None
        if user.get("role") != "admin":
            ids = visible_device_ids(db, user)
            if not ids or not ensure_alert_scope(db):
                return {"month": month, "days": {}}
            where.append("device_id IN :ids")
        q = text("SELECT DATE(`timestamp`) AS d, lv, COUNT(*) AS n FROM alerts WHERE " + " AND ".join(where)
                 + " GROUP BY d, lv")
        if ids is not None:
            q = q.bindparams(bindparam("ids", expanding=True))
            params["ids"] = list(ids)
        days = {}
        for x in db.execute(q, params).fetchall():
            row = dict(x._mapping)
            key = str(row["d"])
            days.setdefault(key, {"crit": 0, "warn": 0, "info": 0})
            if row["lv"] in days[key]:
                days[key][row["lv"]] = int(row["n"])
        return {"month": month, "days": days}

    @r.put("/api/alerts/settings")
    def alerts_settings(req: AlertRetainReq, db=Depends(get_db), user=Depends(require_admin)):
        _incident_tables(db)
        if req.days not in (0, 7, 30, 90):
            raise HTTPException(status_code=400, detail="보관 기간은 7·30·90일 또는 영구(0)만 가능해요")
        db.execute(text("INSERT INTO app_settings (k, v) VALUES ('alert_retain_days', :v) "
                        "ON DUPLICATE KEY UPDATE v = VALUES(v)"), {"v": str(req.days)})
        db.commit()
        return {"ok": True, "retain_days": req.days}

    # ---------- 근무 · 인수인계 · 공지 · 개인 메모 ----------
    def _actor(user):
        return str(user.get("username") or user.get("name") or user.get("sub") or "사용자")[:50]

    def _shift_snapshot(db, user):
        """인수인계 저장 시점의 상태. 일반 사용자는 본인 구역 안의 수치만 본다."""
        is_admin = user.get("role") == "admin"
        ids = None if is_admin else list(visible_device_ids(db, user) or [])
        if ids is not None and not ids:
            return {"open_incidents": 0, "unread_reports": 0, "crit_today": 0}

        def count(sql):
            q = text(sql + ("" if ids is None else " AND device_id IN :ids"))
            params = {}
            if ids is not None:
                q = q.bindparams(bindparam("ids", expanding=True))
                params["ids"] = ids
            return int(db.execute(q, params).scalar() or 0)

        crit = 0
        if ids is None or ensure_alert_scope(db):
            crit = count("SELECT COUNT(*) FROM alerts WHERE lv = 'crit' AND `timestamp` >= DATE(NOW())")
        return {
            "open_incidents": count("SELECT COUNT(*) FROM ai_incidents WHERE status IN ('open', 'block_pending')"),
            "unread_reports": count("SELECT COUNT(*) FROM incident_reports WHERE read_at IS NULL"),
            "crit_today": crit,
        }

    @r.get("/api/shift/handovers")
    def shift_handover_list(limit: int = 30, db=Depends(get_db), user=Depends(get_current_user)):
        _shift_tables(db)
        rows = db.execute(text(
            "SELECT id, shift_date, shift_name, author_name, summary, body, snapshot, created_at "
            "FROM handover_reports ORDER BY id DESC LIMIT :n"),
            {"n": max(1, min(int(limit), 100))}).fetchall()
        items = []
        for x in rows:
            m = dict(x._mapping)
            try:
                snap = json.loads(m["snapshot"]) if m.get("snapshot") else None
            except (TypeError, ValueError):
                snap = None
            items.append({"id": m["id"], "shift_date": str(m["shift_date"]), "shift_name": m["shift_name"],
                          "author_name": m["author_name"], "summary": m["summary"], "body": m["body"],
                          "snapshot": snap, "created_at": str(m["created_at"])})
        return {"items": items, "is_admin": user.get("role") == "admin"}

    @r.post("/api/shift/handovers")
    def shift_handover_create(req: HandoverIn, db=Depends(get_db), user=Depends(get_current_user)):
        _shift_tables(db)
        snap = _shift_snapshot(db, user)
        db.execute(text(
            "INSERT INTO handover_reports (shift_date, shift_name, author_name, summary, body, snapshot, created_at) "
            "VALUES (:d, :s, :a, :m, :b, :snap, :c)"),
            {"s": req.shift_name, "a": _actor(user), "m": req.summary, "b": req.body,
             "snap": json.dumps(snap, ensure_ascii=False), "d": _kst_now().date(), "c": _kst_now()})
        db.commit()
        return {"ok": True, "snapshot": snap}

    @r.delete("/api/shift/handovers/{hid}")
    def shift_handover_delete(hid: int, db=Depends(get_db), user=Depends(require_admin)):
        _shift_tables(db)
        db.execute(text("DELETE FROM handover_reports WHERE id = :i"), {"i": hid})
        db.commit()
        return {"ok": True}

    @r.get("/api/shift/notices")
    def shift_notice_list(db=Depends(get_db), user=Depends(get_current_user)):
        _shift_tables(db)
        is_admin = user.get("role") == "admin"
        if is_admin:
            rows = db.execute(text(
                "SELECT n.id, n.title, n.body, n.author_name, n.pinned, n.created_at FROM notices n "
                "ORDER BY n.pinned DESC, n.id DESC LIMIT 50")).fetchall()
        else:
            rows = db.execute(text(
                "SELECT n.id, n.title, n.body, n.author_name, n.pinned, n.created_at FROM notices n "
                "WHERE " + NOTICE_VISIBLE_USER + " ORDER BY n.pinned DESC, n.id DESC LIMIT 50"),
                {"u": user["user_id"]}).fetchall()
        items = []
        for x in rows:
            m = dict(x._mapping)
            items.append({"id": m["id"], "title": m["title"], "body": m["body"], "author_name": m["author_name"],
                          "pinned": int(m["pinned"] or 0), "created_at": str(m["created_at"]),
                          "target": _notice_targets(db, m["id"]) if is_admin else None})
        return {"items": items, "is_admin": is_admin}

    @r.get("/api/shift/notice-targets")
    def shift_notice_targets(db=Depends(get_db), user=Depends(require_admin)):
        rows = db.execute(text(
            "SELECT d.id, d.name, d.ip, u.username AS owner, u.role AS owner_role FROM devices d "
            "LEFT JOIN users u ON u.id = d.owner_id ORDER BY d.name")).fetchall()
        return {"items": [dict(x._mapping) for x in rows]}

    @r.post("/api/shift/notices")
    def shift_notice_create(req: NoticeIn, db=Depends(get_db), user=Depends(require_admin)):
        _shift_tables(db)
        ids = [] if req.all_users else [int(x) for x in req.device_ids if str(x).isdigit()]
        if not req.all_users and not ids:
            raise HTTPException(status_code=400, detail="받을 장비를 한 대 이상 고르거나 전체로 보내 주세요")
        res = db.execute(text("INSERT INTO notices (title, body, author_name, pinned) VALUES (:t, :b, :a, :p)"),
                         {"t": req.title, "b": req.body, "a": _actor(user), "p": 1 if req.pinned else 0})
        nid = res.lastrowid
        if req.all_users:
            db.execute(text("INSERT INTO notice_targets (notice_id, device_id) VALUES (:n, 0)"), {"n": nid})
        else:
            for d_ in ids:
                db.execute(text("INSERT IGNORE INTO notice_targets (notice_id, device_id) VALUES (:n, :d)"),
                           {"n": nid, "d": d_})
        db.commit()
        return {"ok": True, "id": nid}

    @r.delete("/api/shift/notices/{nid}")
    def shift_notice_delete(nid: int, db=Depends(get_db), user=Depends(require_admin)):
        _shift_tables(db)
        db.execute(text("DELETE FROM notices WHERE id = :i"), {"i": nid})
        db.commit()
        return {"ok": True}

    @r.get("/api/shift/memos")
    def shift_memo_list(db=Depends(get_db), user=Depends(get_current_user)):
        _shift_tables(db)
        rows = db.execute(text(
            "SELECT id, body, created_at, updated_at FROM staff_memos WHERE user_id = :u "
            "ORDER BY updated_at DESC, id DESC"), {"u": user["user_id"]}).fetchall()
        items = [{"id": x._mapping["id"], "body": x._mapping["body"],
                  "created_at": str(x._mapping["created_at"]), "updated_at": str(x._mapping["updated_at"])}
                 for x in rows]
        return {"items": items}

    @r.post("/api/shift/memos")
    def shift_memo_create(req: MemoIn, db=Depends(get_db), user=Depends(get_current_user)):
        _shift_tables(db)
        db.execute(text("INSERT INTO staff_memos (user_id, body) VALUES (:u, :b)"),
                   {"u": user["user_id"], "b": req.body})
        db.commit()
        return {"ok": True}

    @r.put("/api/shift/memos/{mid}")
    def shift_memo_update(mid: int, req: MemoIn, db=Depends(get_db), user=Depends(get_current_user)):
        _shift_tables(db)
        res = db.execute(text("UPDATE staff_memos SET body = :b WHERE id = :i AND user_id = :u"),
                         {"b": req.body, "i": mid, "u": user["user_id"]})
        db.commit()
        if not res.rowcount:
            raise HTTPException(status_code=404, detail="메모를 찾을 수 없어요")
        return {"ok": True}

    @r.delete("/api/shift/memos/{mid}")
    def shift_memo_delete(mid: int, db=Depends(get_db), user=Depends(get_current_user)):
        _shift_tables(db)
        res = db.execute(text("DELETE FROM staff_memos WHERE id = :i AND user_id = :u"),
                         {"i": mid, "u": user["user_id"]})
        db.commit()
        if not res.rowcount:
            raise HTTPException(status_code=404, detail="메모를 찾을 수 없어요")
        return {"ok": True}

    # ---------- 교대 보고 자동 전달 ----------
    def _deliver_shift_report(db, ended):
        """끝난 교대의 보고서를 만들고, 일반 사용자 각자에게 전달 기록을 남긴다. 같은 교대는 한 번만."""
        if db.execute(text("SELECT id FROM shift_reports WHERE report_key = :k"), {"k": ended["key"]}).first():
            return
        s_at, e_at = ended["start_at"], ended["end_at"]
        hos = [dict(x._mapping) for x in db.execute(text(
            "SELECT shift_name, author_name, summary, body FROM handover_reports "
            "WHERE created_at >= :s AND created_at < :e ORDER BY id"), {"s": s_at, "e": e_at}).fetchall()]
        lines = [f"{ended['name']} 교대 ({s_at:%m/%d %H:%M} ~ {e_at:%H:%M})",
                 f"이 교대에 작성된 인수인계 {len(hos)}건"]
        for h_ in hos[:10]:
            lines.append(f"· [{h_['author_name']}] {h_['summary'] or h_['body'][:60]}")
        summary = "\n".join(lines)
        db.execute(text(
            "INSERT INTO shift_reports (report_key, shift_name, shift_date, start_at, end_at, summary) "
            "VALUES (:k, :n, :d, :s, :e, :m)"),
            {"k": ended["key"], "n": ended["name"], "d": s_at.date(), "s": s_at, "e": e_at, "m": summary})
        rid = db.execute(text("SELECT id FROM shift_reports WHERE report_key = :k"), {"k": ended["key"]}).scalar()
        for (uid,) in db.execute(text("SELECT id FROM users WHERE role <> 'admin'")).fetchall():
            snap = _shift_snapshot(db, {"user_id": uid, "role": "user"})
            db.execute(text(
                "INSERT IGNORE INTO shift_deliveries (report_id, user_id, snapshot) VALUES (:r, :u, :snap)"),
                {"r": rid, "u": uid, "snap": json.dumps(snap, ensure_ascii=False)})
        db.commit()

    def _shift_tick(db):
        _shift_tables(db)
        _sim_load(db)
        shifts = _load_plan(db)
        key, name, start_at = _current_shift(shifts, _kst_now())
        raw = _setting_get(db, "shift_current")
        try:
            prev = json.loads(raw) if raw else None
        except (TypeError, ValueError):
            prev = None
        if prev and prev.get("key") != key:
            _deliver_shift_report(db, {"key": prev["key"], "name": prev["name"],
                                       "start_at": datetime.fromisoformat(prev["start_at"]), "end_at": start_at})
        if not prev or prev.get("key") != key:
            _setting_set(db, "shift_current", json.dumps(
                {"key": key, "name": name, "start_at": start_at.isoformat()}, ensure_ascii=False))
            db.commit()

    def _shift_loop(get_db_fn):
        while True:
            try:
                gen = get_db_fn()
                db = next(gen)
                try:
                    _shift_tick(db)
                finally:
                    gen.close()
            except Exception as ex:
                print(f"[shift] 교대 확인 오류: {ex}")
            time.sleep(5)

    threading.Thread(target=_shift_loop, args=(get_db,), daemon=True).start()

    @r.get("/api/shift/plan")
    def shift_plan_get(db=Depends(get_db), user=Depends(get_current_user)):
        _shift_tables(db)
        shifts = _load_plan(db)
        _, name, start_at = _current_shift(shifts, _kst_now())
        return {"shifts": shifts, "current": {"name": name, "start_at": start_at.isoformat(timespec="minutes")}}

    @r.put("/api/shift/plan")
    def shift_plan_put(req: ShiftPlanIn, db=Depends(get_db), user=Depends(require_admin)):
        _shift_tables(db)
        if not (1 <= len(req.shifts) <= 4):
            raise HTTPException(status_code=400, detail="교대는 1~4개까지 설정할 수 있어요")
        clean = []
        for s_ in req.shifts:
            name = str((s_ or {}).get("name", "")).strip()[:10]
            start = str((s_ or {}).get("start", "")).strip()
            if not name:
                raise HTTPException(status_code=400, detail="교대 이름을 입력해 주세요")
            if not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", start):
                raise HTTPException(status_code=400, detail="시작 시각은 HH:MM 형식이어야 해요")
            clean.append({"name": name, "start": start})
        if len({_hm_minutes(s_["start"]) for s_ in clean}) != len(clean):
            raise HTTPException(status_code=400, detail="같은 시각에 두 교대를 둘 수 없어요")
        _setting_set(db, "shift_plan", json.dumps(clean, ensure_ascii=False))
        db.commit()
        return {"ok": True, "shifts": clean}

    @r.get("/api/shift/sim")
    def shift_sim_get(db=Depends(get_db), user=Depends(get_current_user)):
        _sim_load(db)
        return {"on": _SIM["on"], "speed": _SIM["speed"], "now": _kst_now().isoformat(timespec="minutes")}

    @r.put("/api/shift/sim")
    def shift_sim_put(req: SimIn, db=Depends(get_db), user=Depends(require_admin)):
        _shift_tables(db)
        _sim_load(db)
        real_now = datetime.now(KST).replace(tzinfo=None)
        if req.on:
            speed = max(1, min(int(req.speed), 3600))
            if req.start:
                if not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", req.start):
                    raise HTTPException(status_code=400, detail="시작 시각은 HH:MM 형식이어야 해요")
                sim0 = datetime.combine(_kst_now().date(), _tm(int(req.start[:2]), int(req.start[3:])))
            else:
                sim0 = _kst_now()
            _SIM.update(on=True, speed=speed, real0=real_now, sim0=sim0)
        else:
            _SIM.update(on=False, real0=None, sim0=None)
        _sim_save(db)
        return {"ok": True, "on": _SIM["on"], "speed": _SIM["speed"]}

    @r.post("/api/shift/sim/jump")
    def shift_sim_jump(db=Depends(get_db), user=Depends(require_admin)):
        """다음 교대 시각으로 바로 이동한다. 5초 안에 교대가 넘어가고 보고서가 전달된다."""
        _shift_tables(db)
        _sim_load(db)
        if not _SIM["on"]:
            raise HTTPException(status_code=400, detail="시뮬레이션을 먼저 켜 주세요")
        nxt = _next_shift_start(_load_plan(db), _kst_now())
        _SIM.update(real0=datetime.now(KST).replace(tzinfo=None), sim0=nxt)
        _sim_save(db)
        return {"ok": True, "now": nxt.isoformat(timespec="minutes")}

    @r.get("/api/shift/badge")
    def shift_badge(db=Depends(get_db), user=Depends(get_current_user)):
        _shift_tables(db)
        if user.get("role") == "admin":
            return {"unread_reports": 0, "unread_notices": 0}
        rep_n = db.execute(text("SELECT COUNT(*) FROM shift_deliveries WHERE user_id = :u AND read_at IS NULL"),
                           {"u": user["user_id"]}).scalar()
        not_n = db.execute(text(
            "SELECT COUNT(*) FROM notices n LEFT JOIN notice_reads r ON r.notice_id = n.id AND r.user_id = :u "
            "WHERE r.notice_id IS NULL AND " + NOTICE_VISIBLE_USER), {"u": user["user_id"]}).scalar()
        return {"unread_reports": int(rep_n or 0), "unread_notices": int(not_n or 0)}

    @r.get("/api/shift/reports")
    def shift_reports_list(db=Depends(get_db), user=Depends(get_current_user)):
        _shift_tables(db)
        if user.get("role") == "admin":
            rows = [dict(x._mapping) for x in db.execute(text(
                "SELECT r.id, r.shift_name, r.shift_date, r.start_at, r.end_at, r.summary, "
                "(SELECT COUNT(*) FROM shift_deliveries d WHERE d.report_id = r.id) AS delivered, "
                "(SELECT COUNT(*) FROM shift_deliveries d WHERE d.report_id = r.id AND d.read_at IS NOT NULL) AS read_cnt "
                "FROM shift_reports r ORDER BY r.id DESC LIMIT 20")).fetchall()]
            return {"is_admin": True, "items": [
                {"report_id": x["id"], "shift_name": x["shift_name"], "shift_date": str(x["shift_date"]),
                 "start_at": str(x["start_at"]), "end_at": str(x["end_at"]), "summary": x["summary"],
                 "delivered": int(x["delivered"] or 0), "read_cnt": int(x["read_cnt"] or 0)} for x in rows]}
        rows = [dict(x._mapping) for x in db.execute(text(
            "SELECT d.id AS delivery_id, r.id AS report_id, r.shift_name, r.shift_date, r.start_at, r.end_at, "
            "r.summary, d.snapshot, d.delivered_at, d.read_at FROM shift_deliveries d "
            "JOIN shift_reports r ON r.id = d.report_id WHERE d.user_id = :u ORDER BY r.id DESC LIMIT 20"),
            {"u": user["user_id"]}).fetchall()]
        items = []
        for m in rows:
            try:
                snap = json.loads(m["snapshot"]) if m.get("snapshot") else None
            except (TypeError, ValueError):
                snap = None
            items.append({"delivery_id": m["delivery_id"], "report_id": m["report_id"], "shift_name": m["shift_name"],
                          "shift_date": str(m["shift_date"]), "start_at": str(m["start_at"]), "end_at": str(m["end_at"]),
                          "summary": m["summary"], "snapshot": snap, "delivered_at": str(m["delivered_at"]),
                          "read_at": str(m["read_at"]) if m["read_at"] else None})
        return {"is_admin": False, "items": items}

    @r.post("/api/shift/reports/{delivery_id}/read")
    def shift_report_read(delivery_id: int, db=Depends(get_db), user=Depends(get_current_user)):
        _shift_tables(db)
        db.execute(text("UPDATE shift_deliveries SET read_at = COALESCE(read_at, NOW(3)) WHERE id = :i AND user_id = :u"),
                   {"i": delivery_id, "u": user["user_id"]})
        db.commit()
        return {"ok": True}

    @r.get("/api/shift/reports/{report_id}/status")
    def shift_report_status(report_id: int, db=Depends(get_db), user=Depends(require_admin)):
        _shift_tables(db)
        rows = [dict(x._mapping) for x in db.execute(text(
            "SELECT u.username, d.delivered_at, d.read_at FROM shift_deliveries d "
            "JOIN users u ON u.id = d.user_id WHERE d.report_id = :r ORDER BY u.username"), {"r": report_id}).fetchall()]
        return {"items": [{"username": x["username"], "delivered_at": str(x["delivered_at"]),
                           "read_at": str(x["read_at"]) if x["read_at"] else None} for x in rows]}

    @r.post("/api/shift/notices/read-all")
    def shift_notices_read_all(db=Depends(get_db), user=Depends(get_current_user)):
        _shift_tables(db)
        db.execute(text("INSERT IGNORE INTO notice_reads (notice_id, user_id) SELECT n.id, :u FROM notices n WHERE " + NOTICE_VISIBLE_USER),
                   {"u": user["user_id"]})
        db.commit()
        return {"ok": True}

    @r.get("/api/shift/notices/status")
    def shift_notice_status(db=Depends(get_db), user=Depends(require_admin)):
        _shift_tables(db)
        rows = [dict(x._mapping) for x in db.execute(text(
            "SELECT id, title FROM notices ORDER BY id DESC LIMIT 20")).fetchall()]
        items = []
        for n_ in rows:
            rec = _notice_recipient_ids(db, n_["id"])
            read = 0
            if rec:
                read = int(db.execute(text(
                    "SELECT COUNT(*) FROM notice_reads WHERE notice_id = :n AND user_id IN :ids"
                ).bindparams(bindparam("ids", expanding=True)), {"n": n_["id"], "ids": list(rec)}).scalar() or 0)
            t_ = _notice_targets(db, n_["id"])
            label = "전체 사용자" if t_["all"] else f"장비 {len(t_['devices'])}대 담당자"
            items.append({"id": n_["id"], "title": n_["title"], "scope": label, "total": len(rec), "read_cnt": read})
        return {"items": items}

    @r.put("/api/incidents/settings")
    def incident_settings(req: RetainReq, db=Depends(get_db), user=Depends(require_admin)):
        _incident_tables(db)
        db.execute(text("INSERT INTO app_settings (k, v) VALUES ('incident_retain_days', :v) "
                        "ON DUPLICATE KEY UPDATE v = :v"), {"v": str(req.days)})
        db.commit()
        return {"ok": True, "retain_days": req.days}

    # ---------- 장비 백업 (PC 파일 백업 + 폰·아이패드 설정 스냅샷) ----------
    @r.get("/api/backups")
    def list_backups(db=Depends(get_db), user=Depends(get_current_user)):
        ensure_backup_table(db)
        ids = visible_device_ids(db, user)
        devs = [d for d in db.execute(text("SELECT id, name, type FROM devices ORDER BY id")).fetchall()
                if ids is None or d.id in ids]
        bk = []
        for x in db.execute(text("SELECT id, device_id, kind, name, size, created_at FROM device_backups "
                                 "ORDER BY id DESC")).fetchall():
            if ids is None or x.device_id in ids:
                row = dict(x._mapping)
                row["created_at"] = str(row["created_at"])
                bk.append(row)
        return {"can_admin": user.get("role") == "admin", "keep": BACKUP_KEEP,
                "interval_hours": BACKUP_INTERVAL_SEC // 3600,
                "devices": [{"id": d.id, "name": d.name, "kind": "file" if d.type == "pc" else "config"} for d in devs],
                "backups": bk}

    @r.get("/api/backups/{bid}/download")
    def download_backup(bid: int, db=Depends(get_db), user=Depends(get_current_user)):
        from urllib.parse import quote
        from fastapi.responses import Response
        ensure_backup_table(db)
        row = db.execute(text("SELECT device_id, name, kind, data FROM device_backups WHERE id = :i"),
                         {"i": bid}).first()
        if not row:
            raise HTTPException(status_code=404, detail="백업을 찾을 수 없습니다")
        ids = visible_device_ids(db, user)
        if ids is not None and row.device_id not in ids:
            raise HTTPException(status_code=403, detail="이 백업을 볼 권한이 없습니다")
        ctype = "application/zip" if row.kind == "file" else "application/json"
        return Response(content=bytes(row.data), media_type=ctype,
                        headers={"Content-Disposition": "attachment; filename*=UTF-8''" + quote(row.name)})

    @r.post("/api/backups/{device_id}/run")
    def run_backup_now(device_id: int, db=Depends(get_db), user=Depends(require_admin)):
        ensure_backup_table(db)
        dev = db.execute(text("SELECT id, type FROM devices WHERE id = :d"), {"d": device_id}).first()
        if not dev:
            raise HTTPException(status_code=404, detail="장비를 찾을 수 없습니다")
        if dev.type == "pc":        # PC: 에이전트가 다음 확인 때 파일 백업을 실행한다
            cmd = {"id": uuid.uuid4().hex, "incident_id": 0, "mode": "backup", "pid": None,
                   "name": "", "create_time": None}
            with _lock:
                _commands.setdefault(device_id, []).append(cmd)
            return {"queued": True, "kind": "file", "message": "에이전트가 곧 백업을 실행해요 (약 10~20초)"}
        store_backup(db, device_id, "config", f"설정 수동 {datetime.now():%Y%m%d_%H%M}.json",
                     make_config_snapshot(db, device_id))
        return {"queued": False, "kind": "config", "message": "설정 스냅샷을 저장했어요"}

    @r.post("/api/agent/backup", dependencies=[Depends(agent_auth)])
    def agent_backup(req: BackupIn, db=Depends(get_db)):
        import base64
        try:
            data = base64.b64decode(req.data_b64, validate=True)
        except Exception:
            raise HTTPException(status_code=400, detail="잘못된 백업 데이터입니다")
        if not db.execute(text("SELECT id FROM devices WHERE id = :d"), {"d": req.device_id}).first():
            raise HTTPException(status_code=404, detail="등록되지 않은 장비입니다")
        try:
            store_backup(db, req.device_id, "file", req.name, data)
        except ValueError as e:
            raise HTTPException(status_code=413, detail=str(e))
        return {"ok": True, "size": len(data)}

    start_backup_scheduler(get_db)

# ---------- 미등록 기기 등록 (기존 /api/devices/pending, /enroll 은 건드리지 않음) ----------
    @r.get("/api/ai/pending-devices")
    def pending(user=Depends(require_admin)):
        return list(_pending.values())

    @r.post("/api/ai/enroll")
    def enroll(req: EnrollReq, db=Depends(get_db), user=Depends(require_admin)):
        allowed = {"router", "switch", "server", "app", "pc", "mobile", "firewall", "printer", "access-point"}
        if req.type not in allowed:
            raise HTTPException(status_code=400, detail="허용되지 않은 기기 종류입니다")
        try:
            ip = str(ipaddress.ip_address(req.ip.strip()))
        except ValueError:
            raise HTTPException(status_code=400, detail="IP 형식이 올바르지 않습니다")
        cid = req.client_uuid.strip()
        if cid and not _UUID_RE.match(cid):
            raise HTTPException(status_code=400, detail="기기 식별자가 올바르지 않습니다")
        if not req.name.strip():
            raise HTTPException(status_code=400, detail="장비 이름을 입력해 주세요")
        vlan = db.execute(text("SELECT id FROM vlans WHERE code=:c"), {"c": req.vlan_code}).first()
        if not vlan:
            raise HTTPException(status_code=400, detail="Unknown vlan_code")
        try:
            ins = db.execute(text("INSERT INTO devices (name, ip, client_uuid, type, owner_id, x, y, vlan_id) "
                            "VALUES (:n,:ip,:cu,:t,:o,50,50,:v)"),
                       {"n": req.name.strip(), "ip": ip, "cu": cid or None, "t": req.type,
                        "o": user["user_id"], "v": vlan[0]})
            add_alert(db, "info", "기기 등록", f"{req.name.strip()} ({ip}) 등록", "관리자 승인", device_id=getattr(ins, "lastrowid", None))
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(status_code=400, detail="이미 등록된 기기이거나 장비 정보가 올바르지 않습니다")
        _pending.pop(cid or ip, None)  # agent PC는 IP 키로 대기 중
        return {"ok": True}

    # ---------- 기기 본인 화면용 (X-Device-Id 헤더로 기기 구분) ----------
    @r.get("/api/ai/whoami")
    def whoami(request: Request, db=Depends(get_db)):
        direct = request.client.host if request.client else ""
        if direct in ("127.0.0.1", "::1"):  # 서버 PC 자신은 건너뜀
            return {"ip": direct, "local": True, "registered": True}
        cid = _client_uuid(request, required=False)
        row = (db.execute(text("SELECT id, name FROM devices WHERE client_uuid=:c"), {"c": cid}).first()
               if cid else None)
        return {"ip": _client_ip(request), "registered": bool(row), "name": row.name if row else None,
                "id": row.id if row else None}

    @r.post("/api/ai/register-request")
    def register_request(req: SelfRegisterReq, request: Request, db=Depends(get_db)):
        cid = _client_uuid(request)
        ip = _client_ip(request)
        if time.time() - _last_req.get(cid, 0) < 5:
            raise HTTPException(status_code=429, detail="잠시 후 다시 시도해 주세요")
        _last_req[cid] = time.time()
        name = _clean_name(req.name)
        if not name:
            raise HTTPException(status_code=400, detail="기기 이름을 입력해 주세요")
        if req.type not in ALLOWED_TYPES:
            raise HTTPException(status_code=400, detail="허용되지 않은 기기 종류입니다")
        if db.execute(text("SELECT 1 FROM devices WHERE client_uuid=:c"), {"c": cid}).first():
            return {"registered": True}

        auto = os.getenv("AUTO_ENROLL_VLAN", "").strip()  # 시연용: 승인 없이 이 구역에 바로 등록
        if auto:
            vlan = db.execute(text("SELECT id FROM vlans WHERE code=:c"), {"c": auto}).first()
            admin = db.execute(text("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1")).first()
            if not vlan or not admin:
                raise HTTPException(status_code=500, detail="자동 등록 설정(구역 또는 관리자)을 확인해 주세요")
            try:
                db.execute(text("INSERT INTO devices (name, ip, client_uuid, type, owner_id, x, y, vlan_id) "
                                "VALUES (:n,:ip,:cu,:t,:o,50,50,:v)"),
                           {"n": name, "ip": ip, "cu": cid, "t": req.type, "o": admin[0], "v": vlan[0]})
                db.commit()
            except IntegrityError:
                db.rollback()
                raise HTTPException(status_code=400, detail="등록할 수 없습니다")
            _pending.pop(cid, None)
            return {"registered": True}

        if len(_pending) >= 100 and cid not in _pending:
            raise HTTPException(status_code=429, detail="대기 중인 요청이 너무 많습니다")
        _pending[cid] = {"client_uuid": cid, "ip": ip, "hostname": name, "type": req.type, "requested": True}
        return {"registered": False}

    # ---------- 기기 연결 품질 측정 (브라우저가 서버까지 응답 시간을 재서 5초마다 보고) ----------
    @r.post("/api/ai/heartbeat")
    def heartbeat(req: HeartbeatReq, request: Request, db=Depends(get_db)):
        cid = _client_uuid(request)
        if time.time() - _last_hb.get(cid, 0) < 3:
            return {"ok": True, "skipped": True}
        _last_hb[cid] = time.time()
        row = db.execute(text("SELECT id FROM devices WHERE client_uuid=:c"), {"c": cid}).first()
        if not row:
            raise HTTPException(status_code=404, detail="등록되지 않은 기기입니다")
        rtt = None if (req.rtt_ms is None or req.rtt_ms < 0) else min(float(req.rtt_ms), 10000.0)
        db.execute(text("INSERT INTO ping_logs (device_id, ok, rtt_ms) VALUES (:d,:o,:r)"),
                   {"d": row.id, "o": 1 if req.ok else 0, "r": rtt})
        db.execute(text("DELETE FROM ping_logs WHERE device_id=:d AND created_at < NOW() - INTERVAL 1 HOUR"),
                   {"d": row.id})
        db.commit()
        return {"ok": True}

    # ---------- 백업 / 복구 (관리자 전용, JSON) ----------
    BACKUP_FORMAT = "8bit-backup-v1"
    ROLES = {"admin", "user"}

    @r.get("/api/admin/backup")
    def backup_export(db=Depends(get_db), user=Depends(require_admin)):
        def fetch(sql):
            try:
                return [dict(x._mapping) for x in db.execute(text(sql)).fetchall()]
            except Exception:
                return []   # 테이블이 없는 DB에서도 백업이 실패하지 않도록
        tables = {
            "users": fetch("SELECT id, username, password_hash, role FROM users"),
            "vlans": fetch("SELECT id, code, name, cidr, color FROM vlans"),
            "devices": fetch("SELECT id, name, ip, client_uuid, type, owner_id, x, y, vlan_id FROM devices"),
            "links": fetch("SELECT source_id, target_id FROM links"),
            "user_vlans": fetch("SELECT user_id, vlan_id, access_level FROM user_vlans"),
        }
        return {
            "meta": {"format": BACKUP_FORMAT,
                     "created_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
                     "counts": {k: len(v) for k, v in tables.items()}},
            "tables": tables,
        }

    @r.post("/api/admin/restore")
    def backup_restore(req: RestoreReq, db=Depends(get_db), user=Depends(require_admin)):
        if req.confirm != "RESTORE":
            raise HTTPException(status_code=400, detail="확인 문구가 올바르지 않습니다")
        if (req.data.get("meta") or {}).get("format") != BACKUP_FORMAT:
            raise HTTPException(status_code=400, detail="백업 파일 형식이 아닙니다")
        t = req.data.get("tables") or {}
        for k in ("users", "vlans", "devices", "links", "user_vlans"):
            if not isinstance(t.get(k, []), list):
                raise HTTPException(status_code=400, detail=f"{k} 항목이 올바르지 않습니다")
        me = int(user["user_id"])   # 지금 복구를 실행하는 본인 계정은 건드리지 않는다
        try:
            db.execute(text("DELETE FROM links"))
            db.execute(text("DELETE FROM user_vlans"))
            db.execute(text("DELETE FROM devices"))
            db.execute(text("DELETE FROM vlans"))
            for u in t.get("users", []):
                if int(u["id"]) == me:
                    continue
                if u.get("role") not in ROLES:
                    raise ValueError(f"계정 권한이 올바르지 않습니다: {u.get('username')}")
                db.execute(text(
                    "INSERT INTO users (id, username, password_hash, role) VALUES (:i,:u,:p,:r) "
                    "ON DUPLICATE KEY UPDATE username=VALUES(username), password_hash=VALUES(password_hash), role=VALUES(role)"),
                    {"i": int(u["id"]), "u": u["username"], "p": u["password_hash"], "r": u["role"]})
            for v in t.get("vlans", []):
                db.execute(text("INSERT INTO vlans (id, code, name, cidr, color) VALUES (:i,:c,:n,:ci,:co)"),
                           {"i": int(v["id"]), "c": v["code"], "n": v["name"], "ci": v.get("cidr"),
                            "co": v.get("color") or "#a78bfa"})
            for d in t.get("devices", []):
                db.execute(text(
                    "INSERT INTO devices (id, name, ip, client_uuid, type, owner_id, x, y, vlan_id) "
                    "VALUES (:i,:n,:ip,:cu,:ty,:o,:x,:y,:v)"),
                    {"i": int(d["id"]), "n": d["name"], "ip": d["ip"], "cu": d.get("client_uuid") or None,
                     "ty": d["type"], "o": d.get("owner_id"), "x": d.get("x"), "y": d.get("y"),
                     "v": int(d["vlan_id"])})
            for l in t.get("links", []):
                db.execute(text("INSERT INTO links (source_id, target_id) VALUES (:s,:t)"),
                           {"s": int(l["source_id"]), "t": int(l["target_id"])})
            for uv in t.get("user_vlans", []):
                db.execute(text("INSERT INTO user_vlans (user_id, vlan_id, access_level) VALUES (:u,:v,:a)"),
                           {"u": int(uv["user_id"]), "v": int(uv["vlan_id"]), "a": uv.get("access_level") or "view"})
            db.commit()
        except Exception as e:
            db.rollback()
            raise HTTPException(status_code=400, detail=f"복구 실패, 변경 사항을 되돌렸습니다: {e}")
        return {"ok": True, "counts": {k: len(t.get(k, []) or []) for k in ("users", "vlans", "devices", "links", "user_vlans")}}

    # ---------- 연결 요청 (관리자 → 기기 승인) ----------
    def _me(db, request: Request):
        cid = _client_uuid(request, required=False)
        if not cid:
            return None
        return db.execute(text("SELECT id, name FROM devices WHERE client_uuid=:c"), {"c": cid}).first()

    def _linked(db, a, b):
        return db.execute(text("SELECT 1 FROM links WHERE (source_id=:a AND target_id=:b) "
                               "OR (source_id=:b AND target_id=:a)"), {"a": a, "b": b}).first()

    @r.post("/api/ai/connect-request")
    def connect_request(req: ConnReq, db=Depends(get_db), user=Depends(require_admin)):
        if req.source_id == req.target_id:
            raise HTTPException(status_code=400, detail="같은 장비끼리는 연결할 수 없습니다")
        rows = {x.id: x for x in db.execute(
            text("SELECT id, name, type FROM devices WHERE id IN (:a,:b)"),
            {"a": req.source_id, "b": req.target_id})}
        if len(rows) != 2:
            raise HTTPException(status_code=404, detail="Device not found")
        if _linked(db, req.source_id, req.target_id):
            raise HTTPException(status_code=400, detail="이미 연결되어 있는 장비입니다")
        # 승인하는 쪽: mobile 기기 (없으면 대상 기기)
        appr, other = ((req.source_id, req.target_id) if rows[req.source_id].type == "mobile" and rows[req.target_id].type != "mobile"
                       else (req.target_id, req.source_id))
        _conn_reqs[appr] = {"id": uuid.uuid4().hex, "other": other, "appr": appr,
                            "from_name": rows[other].name, "ts": time.time()}
        return {"ok": True}

    @r.get("/api/ai/my-connect-request")
    def my_connect_request(request: Request, db=Depends(get_db)):
        me = _me(db, request)
        q = _conn_reqs.get(me.id) if me else None
        if q and time.time() - q["ts"] > 120:   # 2분 지나면 만료
            _conn_reqs.pop(me.id, None)
            q = None
        return {"request": {"id": q["id"], "from_name": q["from_name"]} if q else None}

    @r.post("/api/ai/connect-respond")
    def connect_respond(res: ConnResp, request: Request, db=Depends(get_db)):
        me = _me(db, request)
        q = _conn_reqs.get(me.id) if me else None
        if not q or q["id"] != res.request_id:
            raise HTTPException(status_code=404, detail="처리할 연결 요청이 없습니다")
        _conn_reqs.pop(me.id, None)
        if res.accept and not _linked(db, q["other"], q["appr"]):
            try:
                db.execute(text("INSERT INTO links (source_id, target_id) VALUES (:a,:b)"),
                           {"a": q["other"], "b": q["appr"]})
                db.commit()
            except IntegrityError:
                db.rollback()
                raise HTTPException(status_code=400, detail="연결 정보가 올바르지 않습니다")
        _conn_done.append({"accepted": res.accept, "a": q["from_name"], "b": me.name})
        return {"ok": True}

    @r.get("/api/ai/connect-results")
    def connect_results(user=Depends(require_admin)):
        out = list(_conn_done)
        _conn_done.clear()
        return {"results": out}

    # ---------- 연결 상태 (에이전트 없는 기기: 핑 기반) ----------
    @r.get("/api/ai/connectivity")
    def connectivity(db=Depends(get_db), user=Depends(get_current_user)):
        agent = {x[0] for x in db.execute(text(
            "SELECT DISTINCT device_id FROM telemetry WHERE timestamp > NOW() - INTERVAL 30 SECOND"))}
        rows = db.execute(text("""
            SELECT device_id, ok, rtt_ms FROM (
              SELECT device_id, ok, rtt_ms,
                     ROW_NUMBER() OVER (PARTITION BY device_id ORDER BY id DESC) AS rn
              FROM ping_logs WHERE created_at > NOW() - INTERVAL 2 MINUTE) t
            WHERE rn <= 10 ORDER BY device_id, rn""")).fetchall()
        by: dict[int, list] = {}
        for x in rows:
            by.setdefault(x.device_id, []).append(x)
        out = {}
        for dev, lst in by.items():
            if dev in agent:
                continue
            lead = 0                       # 최근부터 연속 실패 횟수
            for x in lst:
                if x.ok:
                    break
                lead += 1
            loss = round(100 * sum(1 for x in lst if not x.ok) / len(lst))
            rtts = [x.rtt_ms for x in lst if x.ok and x.rtt_ms is not None]
            avg = sum(rtts) / len(rtts) if rtts else None
            if lead >= 3:
                status = "offline"
            elif loss >= 20:
                status = "unstable"
            elif avg is not None and avg >= 150:
                status = "slow"
            else:
                status = "online"
            out[dev] = {"source": "ping", "status": status, "rtt_ms": avg, "loss": loss}
        # 브라우저 측정 기기(스마트폰 등): 마지막 보고가 20초 넘게 없으면 오프라인
        # (와이파이를 끄면 보고가 끊기므로, 2분 기록 창에 기대지 않고 마지막 보고 시각으로 판정)
        browser_ages = db.execute(text(
            "SELECT d.id AS id, TIMESTAMPDIFF(SECOND, MAX(p.created_at), NOW()) AS age "
            "FROM devices d LEFT JOIN ping_logs p ON p.device_id = d.id "
            "WHERE d.client_uuid IS NOT NULL GROUP BY d.id")).fetchall()
        for row in browser_ages:
            if row.age is None or row.age > 20:
                out[row.id] = {"source": "heartbeat", "status": "offline", "rtt_ms": None, "loss": 100}

        for dev in agent:
            out[dev] = {"source": "agent", "status": "online"}
            
        ids = visible_device_ids(db, user)
        if ids is not None:
            out = {k: v for k, v in out.items() if k in ids}
        return {"devices": out}
    return r