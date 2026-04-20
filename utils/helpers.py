from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone

from config.settings import DTA_EXEC_LOG, HASH_PREFIX_LEN


# =========================
# Temps
# =========================

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# =========================
# Hachage
# =========================

def sha256_hex_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def short_hash_text(s: str, n: int = HASH_PREFIX_LEN) -> str:
    if not s:
        return ""
    return sha256_hex_bytes(s.encode("utf-8"))[:n]


# =========================
# Système de fichiers
# =========================

def safe_makedirs_for_file(path: str) -> None:
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)


def safe_append_line(path: str, line: str) -> None:
    try:
        safe_makedirs_for_file(path)
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())
    except Exception as e:
        print(f"[DTA] ERROR writing {path}: {e}")


def safe_json_append(path: str, obj: dict) -> None:
    safe_append_line(path, json.dumps(obj, ensure_ascii=False))


def ensure_file_exists(path: str) -> None:
    safe_makedirs_for_file(path)
    if not os.path.exists(path):
        open(path, "a", encoding="utf-8").close()


# =========================
# Logging interne
# =========================

def exec_log(msg: str) -> None:
    safe_append_line(DTA_EXEC_LOG, f"[{now_iso()}] {msg}")


# =========================
# Parsing
# =========================

def parse_ts(v) -> str:
    if isinstance(v, str) and v.strip():
        return v
    return now_iso()
