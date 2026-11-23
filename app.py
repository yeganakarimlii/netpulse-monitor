import asyncio
import io
import os
import socket
import ssl
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
import openpyxl
from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

APP_TITLE = "NetPulse Monitor API"
JWT_SECRET = os.getenv("JWT_SECRET", "change_this_secret_in_production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24
DB_PATH = os.getenv("DB_PATH", "/app/data/netpulse.db")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "ChangeMe123!")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()
TZ_OFFSET_MINUTES = int(os.getenv("TIMEZONE_OFFSET_MINUTES", "240"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

app = FastAPI(title=APP_TITLE, version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def now_iso() -> str:
    tz = timezone(timedelta(minutes=TZ_OFFSET_MINUTES))
    return datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")


def get_db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            target TEXT NOT NULL,
            check_type TEXT NOT NULL DEFAULT 'tcp_port',
            port INTEGER,
            http_url TEXT,
            interval_sec INTEGER NOT NULL DEFAULT 30,
            status TEXT NOT NULL DEFAULT 'unknown',
            latency_ms REAL,
            ssl_days_left INTEGER,
            last_error TEXT,
            last_checked TEXT,
            created_at TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS check_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            latency_ms REAL,
            detail TEXT,
            checked_at TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
        )
    """)

    cur.execute("SELECT id FROM users WHERE username = ?", (ADMIN_USERNAME,))
    if not cur.fetchone():
        cur.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (ADMIN_USERNAME, pwd_context.hash(ADMIN_PASSWORD), now_iso()),
        )

    cur.execute("SELECT COUNT(*) as cnt FROM devices")
    if cur.fetchone()["cnt"] == 0:
        samples = [
            ("Cloudflare DNS Primary", "1.1.1.1", "tcp_port", 53, None, 30),
            ("Google DNS", "8.8.8.8", "icmp_ping", None, None, 30),
            ("GitHub HTTPS", "github.com", "http_ssl", 443, "https://github.com", 60),
            ("Local Gateway Sample", "192.168.1.1", "icmp_ping", None, None, 30),
        ]
        for name, target, ctype, port, url, interval in samples:
            cur.execute(
                """
                INSERT INTO devices (name, target, check_type, port, http_url, interval_sec, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 'unknown', ?)
                """,
                (name, target, ctype, port, url, interval, now_iso()),
            )

    conn.commit()
    conn.close()


class LoginRequest(BaseModel):
    username: str
    password: str


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=6)


class DeviceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    target: str = Field(min_length=1, max_length=255)
    check_type: str = Field(default="tcp_port", pattern="^(icmp_ping|tcp_port|http_ssl)$")
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    http_url: Optional[str] = None
    interval_sec: int = Field(default=30, ge=10, le=3600)


class DeviceUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    target: Optional[str] = Field(default=None, min_length=1, max_length=255)
    check_type: Optional[str] = Field(default=None, pattern="^(icmp_ping|tcp_port|http_ssl)$")
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    http_url: Optional[str] = None
    interval_sec: Optional[int] = Field(default=None, ge=10, le=3600)


def create_access_token(username: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    payload = {"sub": username, "exp": expire}
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")


async def send_telegram_alert(message: str) -> None:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML",
    }
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            await client.post(url, json=payload)
    except Exception:
        pass


def check_icmp_ping(host: str) -> tuple[str, Optional[float], str]:
    start = time.perf_counter()
    try:
        proc = os.system(f"ping -c 1 -W 2 {host} >/dev/null 2>&1")
        elapsed = round((time.perf_counter() - start) * 1000, 2)
        if proc == 0:
            return "online", elapsed, f"ICMP reply in {elapsed} ms"
        return "offline", None, "Ping timeout or unreachable"
    except Exception as exc:
        return "offline", None, str(exc)


def check_tcp_port(host: str, port: int) -> tuple[str, Optional[float], str]:
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=3.0):
            elapsed = round((time.perf_counter() - start) * 1000, 2)
            return "online", elapsed, f"TCP/{port} open ({elapsed} ms)"
    except Exception as exc:
        return "offline", None, f"TCP/{port} closed/unreachable: {exc}"


def get_ssl_expiry_days(hostname: str, port: int = 443) -> Optional[int]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=4.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                if not not_after:
                    return None
                exp_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days = (exp_dt - datetime.now(timezone.utc)).days
                return days
    except Exception:
        return None


async def check_http_ssl(
    target: str, http_url: Optional[str], port: Optional[int]
) -> tuple[str, Optional[float], Optional[int], str]:
    url = (http_url or "").strip()
    if not url:
        scheme = "https" if (port in (None, 443)) else "http"
        host_part = target if (port in (None, 80, 443)) else f"{target}:{port}"
        url = f"{scheme}://{host_part}"

    ssl_host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    ssl_days = get_ssl_expiry_days(ssl_host, port or 443) if url.startswith("https://") else None

    start = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True, verify=False) as client:
            resp = await client.get(url)
            elapsed = round((time.perf_counter() - start) * 1000, 2)
            if 200 <= resp.status_code < 500:
                detail = f"HTTP {resp.status_code} ({elapsed} ms)"
                if ssl_days is not None:
                    detail += f", SSL: {ssl_days}d left"
                return "online", elapsed, ssl_days, detail
            return "offline", elapsed, ssl_days, f"HTTP {resp.status_code}"
    except Exception as exc:
        return "offline", None, ssl_days, f"HTTP error: {exc}"


async def run_device_check(device_row: sqlite3.Row) -> dict:
    ctype = device_row["check_type"]
    target = device_row["target"].strip()
    port = device_row["port"]
    http_url = device_row["http_url"]
    prev_status = device_row["status"]

    ssl_days: Optional[int] = device_row["ssl_days_left"]
    if ctype == "icmp_ping":
        new_status, latency, detail = check_icmp_ping(target)
    elif ctype == "http_ssl":
        new_status, latency, ssl_days, detail = await check_http_ssl(target, http_url, port)
    else:
        target_port = port or 80
        new_status, latency, detail = check_tcp_port(target, target_port)

    checked_at = now_iso()
    last_error = None if new_status == "online" else detail

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE devices
        SET status = ?, latency_ms = ?, ssl_days_left = ?, last_error = ?, last_checked = ?
        WHERE id = ?
        """,
        (new_status, latency, ssl_days, last_error, checked_at, device_row["id"]),
    )
    cur.execute(
        """
        INSERT INTO check_logs (device_id, status, latency_ms, detail, checked_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (device_row["id"], new_status, latency, detail, checked_at),
    )
    cur.execute(
        """
        DELETE FROM check_logs
        WHERE device_id = ? AND id NOT IN (
            SELECT id FROM check_logs WHERE device_id = ? ORDER BY id DESC LIMIT 100
        )
        """,
        (device_row["id"], device_row["id"]),
    )
    conn.commit()
    conn.close()

    if prev_status in ("online", "offline") and prev_status != new_status:
        icon = "🔴" if new_status == "offline" else "🟢"
        msg = (
            f"{icon} <b>NetPulse Alert</b>\n"
            f"<b>Cihaz:</b> {device_row['name']}\n"
            f"<b>Hədəf:</b> <code>{target}</code>\n"
            f"<b>Status:</b> {prev_status.upper()} → <b>{new_status.upper()}</b>\n"
            f"<b>Detal:</b> {detail}\n"
            f"<b>Vaxt:</b> {checked_at}"
        )
        await send_telegram_alert(msg)

    return {
        "id": device_row["id"],
        "status": new_status,
        "latency_ms": latency,
        "ssl_days_left": ssl_days,
        "detail": detail,
        "last_checked": checked_at,
    }


async def background_monitor_loop() -> None:
    await asyncio.sleep(2)
    while True:
        try:
            conn = get_db()
            rows = conn.execute("SELECT * FROM devices ORDER BY id ASC").fetchall()
            conn.close()
            for row in rows:
                await run_device_check(row)
        except Exception:
            pass
        await asyncio.sleep(20)


@app.on_event("startup")
async def on_startup() -> None:
    init_db()
    asyncio.create_task(background_monitor_loop())


@app.get("/api/health")
def health_check():
    return {"status": "ok", "service": APP_TITLE, "time": now_iso()}


@app.post("/api/auth/login")
def login(req: LoginRequest):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (req.username.strip(),)).fetchone()
    conn.close()
    if not user or not pwd_context.verify(req.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Yanlış istifadəçi adı və ya şifrə")
    token = create_access_token(user["username"])
    return {"access_token": token, "token_type": "bearer", "username": user["username"]}


@app.post("/api/auth/change-password")
def change_password(req: PasswordChangeRequest, username: str = Depends(get_current_user)):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not user or not pwd_context.verify(req.current_password, user["password_hash"]):
        conn.close()
        raise HTTPException(status_code=400, detail="Cari şifrə yanlışdır")
    new_hash = pwd_context.hash(req.new_password)
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user["id"]))
    conn.commit()
    conn.close()
    return {"message": "Şifrə uğurla yeniləndi"}


@app.get("/api/devices")
def list_devices(
    search: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None),
    _: str = Depends(get_current_user),
):
    conn = get_db()
    rows = conn.execute("SELECT * FROM devices ORDER BY id DESC").fetchall()
    conn.close()

    devices = [dict(r) for r in rows]
    if search:
        s = search.lower().strip()
        devices = [d for d in devices if s in d["name"].lower() or s in d["target"].lower()]
    if status_filter and status_filter != "all":
        devices = [d for d in devices if d["status"] == status_filter]

    total = len(rows)
    online = sum(1 for r in rows if r["status"] == "online")
    offline = sum(1 for r in rows if r["status"] == "offline")
    unknown = sum(1 for r in rows if r["status"] == "unknown")
    latencies = [r["latency_ms"] for r in rows if r["latency_ms"] is not None]
    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0.0

    return {
        "summary": {
            "total": total,
            "online": online,
            "offline": offline,
            "unknown": unknown,
            "avg_latency_ms": avg_latency,
        },
        "devices": devices,
    }


@app.post("/api/devices", status_code=201)
async def create_device(payload: DeviceCreate, _: str = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO devices (name, target, check_type, port, http_url, interval_sec, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 'unknown', ?)
        """,
        (
            payload.name.strip(),
            payload.target.strip(),
            payload.check_type,
            payload.port,
            payload.http_url.strip() if payload.http_url else None,
            payload.interval_sec,
            now_iso(),
        ),
    )
    device_id = cur.lastrowid
    row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    conn.commit()
    conn.close()

    await run_device_check(row)
    conn = get_db()
    updated = dict(conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone())
    conn.close()
    return updated


@app.put("/api/devices/{device_id}")
def update_device(device_id: int, payload: DeviceUpdate, _: str = Depends(get_current_user)):
    conn = get_db()
    existing = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="Cihaz tapılmadı")

    data = dict(existing)
    updates = payload.model_dump(exclude_unset=True)
    for k, v in updates.items():
        data[k] = v

    conn.execute(
        """
        UPDATE devices
        SET name = ?, target = ?, check_type = ?, port = ?, http_url = ?, interval_sec = ?
        WHERE id = ?
        """,
        (
            data["name"],
            data["target"],
            data["check_type"],
            data["port"],
            data["http_url"],
            data["interval_sec"],
            device_id,
        ),
    )
    conn.commit()
    updated = dict(conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone())
    conn.close()
    return updated


@app.delete("/api/devices/{device_id}")
def delete_device(device_id: int, _: str = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM devices WHERE id = ?", (device_id,))
    conn.commit()
    deleted = cur.rowcount
    conn.close()
    if deleted == 0:
        raise HTTPException(status_code=404, detail="Cihaz tapılmadı")
    return {"deleted": True, "id": device_id}


@app.post("/api/devices/{device_id}/check")
async def check_single_device(device_id: int, _: str = Depends(get_current_user)):
    conn = get_db()
    row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Cihaz tapılmadı")
    result = await run_device_check(row)
    return result


@app.post("/api/devices/check-all")
async def check_all_devices(_: str = Depends(get_current_user)):
    conn = get_db()
    rows = conn.execute("SELECT * FROM devices ORDER BY id ASC").fetchall()
    conn.close()
    results = []
    for r in rows:
        results.append(await run_device_check(r))
    return {"checked_count": len(results), "results": results}


@app.get("/api/devices/{device_id}/logs")
def get_device_logs(device_id: int, _: str = Depends(get_current_user)):
    conn = get_db()
    logs = conn.execute(
        "SELECT * FROM check_logs WHERE device_id = ? ORDER BY id DESC LIMIT 30",
        (device_id,),
    ).fetchall()
    conn.close()
    return {"logs": [dict(l) for l in logs]}


@app.get("/api/export/xlsx")
def export_xlsx(_: str = Depends(get_current_user)):
    conn = get_db()
    rows = conn.execute("SELECT * FROM devices ORDER BY id ASC").fetchall()
    conn.close()

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Monitoring Report"
    headers = [
        "ID",
        "Device Name",
        "Target",
        "Check Type",
        "Port",
        "HTTP URL",
        "Status",
        "Latency (ms)",
        "SSL Days Left",
        "Last Error",
        "Last Checked",
    ]
    ws.append(headers)

    for r in rows:
        ws.append([
            r["id"],
            r["name"],
            r["target"],
            r["check_type"],
            r["port"],
            r["http_url"],
            r["status"],
            r["latency_ms"],
            r["ssl_days_left"],
            r["last_error"],
            r["last_checked"],
        ])

    for col in ws.columns:
        max_len = max(len(str(cell.value or "")) for cell in col) + 3
        ws.column_dimensions[col[0].column_letter].width = min(max_len, 42)

    stream = io.BytesIO()
    wb.save(stream)
    stream.seek(0)
    filename = f"netpulse-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.xlsx"
    return StreamingResponse(
        stream,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.post("/api/import/xlsx")
async def import_xlsx(file: UploadFile = File(...), _: str = Depends(get_current_user)):
    if not file.filename.lower().endswith(".xlsx"):
        raise HTTPException(status_code=400, detail="Yalnız .xlsx faylları dəstəklənir")

    content = await file.read()
    wb = openpyxl.load_workbook(io.BytesIO(content))
    ws = wb.active

    imported = 0
    conn = get_db()
    cur = conn.cursor()

    for idx, row in enumerate(ws.iter_rows(values_only=True), start=1):
        if idx == 1:
            continue
        if not row or not row[0] or not row[1]:
            continue
        name = str(row[0]).strip()
        target = str(row[1]).strip()
        ctype = str(row[2]).strip().lower() if len(row) > 2 and row[2] else "tcp_port"
        if ctype not in ("icmp_ping", "tcp_port", "http_ssl"):
            ctype = "tcp_port"
        port = None
        if len(row) > 3 and row[3] is not None and str(row[3]).strip() != "":
            try:
                port = int(float(str(row[3]).strip()))
            except ValueError:
                port = None
        http_url = str(row[4]).strip() if len(row) > 4 and row[4] else None
        interval_sec = 30
        if len(row) > 5 and row[5] is not None and str(row[5]).strip() != "":
            try:
                interval_sec = max(10, min(3600, int(float(str(row[5]).strip()))))
            except ValueError:
                interval_sec = 30

        cur.execute(
            """
            INSERT INTO devices (name, target, check_type, port, http_url, interval_sec, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'unknown', ?)
            """,
            (name, target, ctype, port, http_url, interval_sec, now_iso()),
        )
        imported += 1

    conn.commit()
    conn.close()
    return {"imported": imported, "message": f"{imported} cihaz uğurla idxal edildi"}