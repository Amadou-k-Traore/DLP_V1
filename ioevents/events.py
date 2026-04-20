from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from threading import Event
from typing import Iterable, Optional

from config.settings import POLL_SLEEP_SEC
from utils.helpers import ensure_file_exists, parse_ts, sha256_file


@dataclass(frozen=True)
class LogEvent:
    etype:      str
    username:   str
    session_id: str
    request_id: str
    ts:         str
    text:       Optional[str] = None
    path:       Optional[str] = None
    sha256:     Optional[str] = None
    filename:   Optional[str] = None
    mime:       Optional[str] = None


# =========================
# Gestion du marqueur de position
# =========================

def _pos_path(jsonl_path: str) -> str:
    return jsonl_path + ".pos"


def _read_pos(jsonl_path: str) -> int:
    pos_file = _pos_path(jsonl_path)
    try:
        with open(pos_file, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if content.isdigit():
                return int(content)
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return 0


def _write_pos(jsonl_path: str, position: int) -> None:
    pos_file = _pos_path(jsonl_path)
    try:
        with open(pos_file, "w", encoding="utf-8") as f:
            f.write(str(position))
    except Exception:
        pass


def _reset_pos(jsonl_path: str) -> None:
    _write_pos(jsonl_path, 0)


# =========================
# Lecture continue avec marqueur de position
# =========================

def tail_jsonl(path: str, stop: Event) -> Iterable[dict]:
    """
    Lit les nouvelles lignes d'un fichier JSONL en continu.

    Meilleure pratique entreprise — marqueur de position (.pos) :
      - Au démarrage, reprend depuis la dernière position lue
      - Après chaque ligne, sauvegarde la position dans path + '.pos'
      - Si le DTA redémarre -> reprend exactement la ou il s'etait arrete
      - Aucun message rate, aucun message retraite

    Exemple :
      chat_input.jsonl      <- journal des messages
      chat_input.jsonl.pos  <- marque-page (ex: "1842")

    Cas geres :
      - Premiere fois (pas de .pos) -> lit depuis le debut
      - Redemarrage normal -> reprend depuis .pos
      - Fichier vide/recree (taille < position) -> repart de 0
    """
    ensure_file_exists(path)

    saved_pos = _read_pos(path)

    f = open(path, "r", encoding="utf-8", errors="ignore")

    f.seek(0, os.SEEK_END)
    file_size = f.tell()

    if saved_pos > file_size:
        saved_pos = 0
        _reset_pos(path)

    f.seek(saved_pos)

    while not stop.is_set():
        line = f.readline()

        if not line:
            time.sleep(POLL_SLEEP_SEC)
            continue

        line_stripped = line.strip()

        current_pos = f.tell()
        _write_pos(path, current_pos)

        if not line_stripped:
            continue

        try:
            obj = json.loads(line_stripped)
            if isinstance(obj, dict):
                yield obj
        except Exception:
            continue

    try:
        f.close()
    except Exception:
        pass


# =========================
# Parsing d'un evenement brut
# =========================

def parse_event(obj: dict) -> Optional[LogEvent]:
    etype = str(obj.get("type") or obj.get("event_type") or "").strip().lower()

    if etype not in ("text", "image", "audio"):
        if "text" in obj and isinstance(obj.get("text"), str):
            etype = "text"
        elif obj.get("media_type") in ("image", "audio"):
            etype = obj.get("media_type")
        else:
            return None

    username   = str(obj.get("username")   or obj.get("user")    or "unknown")
    session_id = str(obj.get("session_id") or obj.get("session") or "unknown")
    request_id = str(
        obj.get("request_id") or obj.get("req_id") or obj.get("id") or "unknown"
    )
    ts = parse_ts(obj.get("ts") or obj.get("timestamp"))

    if etype == "text":
        text = obj.get("text") or obj.get("content") or ""
        if not isinstance(text, str):
            return None
        return LogEvent(
            etype="text",
            username=username,
            session_id=session_id,
            request_id=request_id,
            ts=ts,
            text=text,
        )

    media_path = obj.get("path") or obj.get("file_path")
    sha        = obj.get("sha256") or obj.get("file_sha256")
    fn         = obj.get("filename")
    mime       = obj.get("mime")

    if isinstance(media_path, str) and media_path and not str(sha or "").strip():
        try:
            sha = sha256_file(media_path)
        except Exception:
            sha = None

    return LogEvent(
        etype=etype,
        username=username,
        session_id=session_id,
        request_id=request_id,
        ts=ts,
        path=str(media_path) if isinstance(media_path, str) else None,
        sha256=str(sha).lower() if sha else None,
        filename=str(fn) if isinstance(fn, str) else None,
        mime=str(mime) if isinstance(mime, str) else None,
    )
