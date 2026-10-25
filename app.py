from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import streamlit as st

APP_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("FIM_DB_PATH", APP_DIR / "fim.db"))
MAX_FILE_BYTES = int(os.getenv("FIM_MAX_FILE_BYTES", str(50 * 1024 * 1024)))
IGNORED_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules"}

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS baseline (
        path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
        mtime_ns INTEGER NOT NULL, captured_at TEXT NOT NULL
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, path TEXT NOT NULL,
        event_type TEXT NOT NULL, old_hash TEXT, new_hash TEXT,
        details TEXT NOT NULL, created_at TEXT NOT NULL
    )""")
    conn.commit()
    return conn

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def safe_scan(root: Path) -> Iterable[Path]:
    root = root.expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError("Select an existing directory.")
    for current, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        for name in names:
            p = Path(current) / name
            try:
                if p.is_symlink() or not p.is_file():
                    continue
                if p.stat().st_size > MAX_FILE_BYTES:
                    continue
                yield p.resolve()
            except (OSError, PermissionError):
                continue

def log_event(conn, path, kind, old_hash, new_hash, details):
    conn.execute(
        "INSERT INTO events(path,event_type,old_hash,new_hash,details,created_at) VALUES(?,?,?,?,?,?)",
        (str(path), kind, old_hash, new_hash, details, now())
    )

def establish_baseline(root: Path):
    conn = connect()
    count = 0
    for path in safe_scan(root):
        try:
            stt = path.stat()
            digest = sha256_file(path)
            conn.execute("""INSERT INTO baseline(path,sha256,size,mtime_ns,captured_at)
                VALUES(?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET
                sha256=excluded.sha256,size=excluded.size,mtime_ns=excluded.mtime_ns,
                captured_at=excluded.captured_at""",
                (str(path), digest, stt.st_size, stt.st_mtime_ns, now()))
            count += 1
        except OSError:
            continue
    conn.commit()
    conn.close()
    return count

def scan_for_changes(root: Path):
    conn = connect()
    known = {r["path"]: dict(r) for r in conn.execute("SELECT * FROM baseline")}
    seen = set()
    counts = {"modified": 0, "new": 0, "deleted": 0, "errors": 0}
    for path in safe_scan(root):
        key = str(path)
        seen.add(key)
        try:
            stt = path.stat()
            digest = sha256_file(path)
            previous = known.get(key)
            if previous is None:
                log_event(conn, key, "NEW_FILE", None, digest, "File is not in the trusted baseline.")
                counts["new"] += 1
            elif digest != previous["sha256"]:
                log_event(conn, key, "MODIFIED", previous["sha256"], digest,
                          "SHA-256 differs from the trusted baseline.")
                counts["modified"] += 1
        except OSError as exc:
            log_event(conn, key, "SCAN_ERROR", None, None, str(exc))
            counts["errors"] += 1

    # Only report missing paths beneath the selected root.
    root_resolved = str(root.expanduser().resolve())
    for key, previous in known.items():
        try:
            if os.path.commonpath([root_resolved, str(Path(key).resolve())]) != root_resolved:
                continue
        except (ValueError, OSError):
            continue
        if key not in seen and not Path(key).exists():
            log_event(conn, key, "DELETED", previous["sha256"], None,
                      "Previously baselined file is missing.")
            counts["deleted"] += 1
    conn.commit()
    conn.close()
    return counts

def analyze_event_locally(event: dict) -> dict:
    """Conservative fallback. Replace with a verified model endpoint when configured."""
    kind = event.get("event_type", "")
    path = event.get("path", "")
    critical_terms = ("/etc/", "\\windows\\system32\\", ".ssh/", "authorized_keys",
                      "startup", "security", "firewall", "sudoers")
    critical = any(term in path.lower() for term in critical_terms)
    if kind in {"MODIFIED", "DELETED"} and critical:
        level = "High"
        rationale = "A protected-looking system or access-control path changed; verify authorization."
    elif kind in {"MODIFIED", "DELETED"}:
        level = "Medium"
        rationale = "A previously baselined file changed or disappeared; confirm the change was authorized."
    elif kind == "NEW_FILE":
        level = "Low"
        rationale = "A file appeared outside the baseline; verify whether it belongs there."
    else:
        level = "Info"
        rationale = "Review the scan event and investigate if unexpected."
    return {"risk": level, "summary": rationale,
            "ai_status": "Local rule-based fallback; no remote AI inference performed."}

st.set_page_config(page_title="HashGuardian", page_icon="🛡️", layout="wide")
st.title("🛡️ HashGuardian")
st.caption("SHA-256 integrity verification with an optional AI analysis integration.")
st.warning("Prototype: create the baseline from a trusted, clean state. Store the database and backups with appropriate access controls; this app does not prevent tampering by a privileged attacker.")

with st.sidebar:
    st.header("Monitor configuration")
    folder = st.text_input("Directory to monitor", value=str(Path.home()))
    st.caption(f"Files larger than {MAX_FILE_BYTES // (1024*1024)} MB and common dependency folders are skipped.")
    if st.button("Create / refresh baseline", type="primary", use_container_width=True):
        try:
            n = establish_baseline(Path(folder))
            st.success(f"Baseline recorded for {n} files.")
        except Exception as e:
            st.error(str(e))
    if st.button("Scan for changes", use_container_width=True):
        try:
            result = scan_for_changes(Path(folder))
            st.session_state["last_scan"] = result
            st.success("Scan complete.")
        except Exception as e:
            st.error(str(e))

conn = connect()
baseline_count = conn.execute("SELECT COUNT(*) FROM baseline").fetchone()[0]
event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
unresolved_count = conn.execute("SELECT COUNT(*) FROM events WHERE event_type IN ('MODIFIED','NEW_FILE','DELETED','SCAN_ERROR')").fetchone()[0]
c1, c2, c3 = st.columns(3)
c1.metric("Baselined files", baseline_count)
c2.metric("Recorded events", event_count)
c3.metric("Events requiring review", unresolved_count)

if "last_scan" in st.session_state:
    st.subheader("Latest scan results")
    st.json(st.session_state["last_scan"])

st.subheader("Recent events")
rows = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 200").fetchall()
conn.close()
if rows:
    event_list = [dict(r) for r in rows]
    for event in event_list[:20]:
        with st.expander(f'#{event["id"]} · {event["event_type"]} · {event["path"]}'):
            st.write("Timestamp:", event["created_at"])
            st.write("Details:", event["details"])
            if event["old_hash"]:
                st.code("Old SHA-256: " + event["old_hash"])
            if event["new_hash"]:
                st.code("New SHA-256: " + event["new_hash"])
            st.write("Risk assessment")
            st.json(analyze_event_locally(event))
    st.download_button("Export event log (JSON)", json.dumps(event_list, indent=2),
                       file_name="fim-events.json", mime="application/json")
else:
    st.info("No events yet. Choose a directory, establish a baseline from a trusted state, then scan after changes occur.")

st.subheader("Adaption Labs integration")
st.write("Adaption's documented APIs support data preparation and model-training workflows. This prototype deliberately does not invent an inference endpoint. To connect a trained model, implement a server-side adapter in `ai_adapter.py` using the exact endpoint and authentication contract provided for your deployed model.")
st.caption("Do not upload file contents, secrets, or sensitive paths to a third-party model unless your organization's policy permits it.")
