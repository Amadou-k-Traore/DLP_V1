#!/usr/bin/env python3
"""
DTA — Data Threat Analyzer
Pipeline C1-C4 avec filtre LLM gemma3:4b via Ollama

Architecture :
  Ollama (port 11434) → gemma3:4b  (filtre DTA — 3.3 GB)
  Ollama (port 11434) → llama3.1   (chat Backend — 4.9 GB)

Pas de contention car appeles en sequence :
  1. gemma3:4b classifie le prompt (filtre)
  2. Si non sensible → llama3.1 genere la reponse (chat)
  Les deux ne sont jamais appeles simultanement.
"""
from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import time
from queue import Queue, Empty
from threading import Event, Thread

from config.settings import (
    PG_HOST, PG_PORT, PG_USER, PG_DB,
    CHAT_LOG_JSONL, MEDIA_LOG_JSONL,
    REFRESH_INTERVAL_SEC,
    QUEUE_MAX_SIZE, QUEUE_NUM_WORKERS,
    LLM_FILTER_MODEL, LLM_FILTER_ENABLED,
    OLLAMA_BASE_URL, LLM_FILTER_TIMEOUT,
)
from db.store import PostgresStore
from detection.media import detect_media
from detection.ner import get_nlp
from detection.text import detect_text
from detection.llm_filter import is_llm_available
from ioevents.cache import ReferenceCache
from ioevents.events import LogEvent, parse_event, tail_jsonl
from utils.helpers import ensure_file_exists, exec_log


def _refresh_refs(cache: ReferenceCache, pg: PostgresStore, stop: Event) -> None:
    exec_log("thread refresh demarre")
    try:
        while not stop.is_set():
            try:
                rows = pg.load_sensitive_media()
                cache.rebuild(rows)
                text_count = pg.count_sensitive_text()
                exec_log(f"refs refreshed: media_rows={len(rows)} sensitive_text_count={text_count}")
            except Exception as e:
                exec_log(f"refresh error: {repr(e)}")
            for _ in range(REFRESH_INTERVAL_SEC):
                if stop.is_set():
                    break
                time.sleep(1)
    finally:
        exec_log("thread refresh arrete")


_text_queue:  Queue = Queue(maxsize=QUEUE_MAX_SIZE)
_media_queue: Queue = Queue(maxsize=QUEUE_MAX_SIZE)


def _ingest_chat(stop: Event) -> None:
    exec_log(f"thread ingest_chat demarre — lecture: {CHAT_LOG_JSONL}")
    try:
        for obj in tail_jsonl(CHAT_LOG_JSONL, stop):
            ev = parse_event(obj)
            if not ev or ev.etype != "text":
                continue
            try:
                _text_queue.put_nowait(ev)
            except Exception:
                exec_log("text_queue pleine — evenement ignore")
    finally:
        exec_log("thread ingest_chat arrete")


def _ingest_media(stop: Event) -> None:
    exec_log(f"thread ingest_media demarre — lecture: {MEDIA_LOG_JSONL}")
    try:
        for obj in tail_jsonl(MEDIA_LOG_JSONL, stop):
            ev = parse_event(obj)
            if not ev or ev.etype not in ("image", "audio"):
                continue
            try:
                _media_queue.put_nowait(ev)
            except Exception:
                exec_log("media_queue pleine — evenement ignore")
    finally:
        exec_log("thread ingest_media arrete")


def _worker_text(worker_id: int, cache: ReferenceCache, pg: PostgresStore, stop: Event) -> None:
    exec_log(f"worker_text[{worker_id}] demarre")
    try:
        while not stop.is_set():
            try:
                ev: LogEvent = _text_queue.get(timeout=0.5)
            except Empty:
                continue
            try:
                detect_text(cache, pg, ev)
            except Exception as e:
                exec_log(f"worker_text[{worker_id}] error: {repr(e)}")
            finally:
                _text_queue.task_done()
    finally:
        exec_log(f"worker_text[{worker_id}] arrete")


def _worker_media(worker_id: int, cache: ReferenceCache, pg: PostgresStore, stop: Event) -> None:
    exec_log(f"worker_media[{worker_id}] demarre")
    try:
        while not stop.is_set():
            try:
                ev: LogEvent = _media_queue.get(timeout=0.5)
            except Empty:
                continue
            try:
                detect_media(cache, pg, ev)
            except Exception as e:
                exec_log(f"worker_media[{worker_id}] error: {repr(e)}")
            finally:
                _media_queue.task_done()
    finally:
        exec_log(f"worker_media[{worker_id}] arrete")


def _preflight(pg: PostgresStore) -> None:
    from config.settings import CUSTOM_ALERT_LOG, UI_DECISIONS_JSONL, DTA_EXEC_LOG
    for path in (CHAT_LOG_JSONL, MEDIA_LOG_JSONL, CUSTOM_ALERT_LOG,
                 UI_DECISIONS_JSONL, DTA_EXEC_LOG):
        ensure_file_exists(path)

    info = pg.ping()
    exec_log(f"DB ping OK: db={info.get('db')} host={PG_HOST} port={PG_PORT} user={PG_USER}")
    tables = pg.check_tables()
    exec_log(f"DB tables: sensitive_text={tables['sensitive_text']} user_policy={tables['user_policy']}")

    if LLM_FILTER_ENABLED:
        exec_log(
            f"LLM filtre: ACTIVE — moteur=Ollama "
            f"modele={LLM_FILTER_MODEL} "
            f"timeout={LLM_FILTER_TIMEOUT}s"
        )
        exec_log("LLM flux: C1(classify) → C2(extract) → C3(fuzzy) → C4(jaccard) → N2(skeleton) → N3(intent)")
        is_llm_available()
    else:
        exec_log("LLM filtre: DESACTIVE — mode fallback fuzzy/jaccard")


def main() -> None:
    stop  = Event()
    pg    = PostgresStore()
    cache = ReferenceCache()

    exec_log("DTA START — Pipeline C1-C4 qwen3:1.7b + llama3.1 via Ollama")
    exec_log(
        f"Config: PG_HOST={PG_HOST} workers={QUEUE_NUM_WORKERS} "
        f"llm={'ON' if LLM_FILTER_ENABLED else 'OFF'} "
        f"llm_model={LLM_FILTER_MODEL} timeout={LLM_FILTER_TIMEOUT}s"
    )

    try:
        _preflight(pg)
    except Exception as e:
        exec_log(f"PRECHECK FAILED: {repr(e)}")
        raise

    try:
        cache.rebuild(pg.load_sensitive_media())
        exec_log("initial refs loaded OK")
    except Exception as e:
        exec_log(f"initial refs failed: {repr(e)}")

    get_nlp()

    threads: list[Thread] = [
        Thread(target=_refresh_refs, args=(cache, pg, stop), daemon=True, name="refresh"),
        Thread(target=_ingest_chat,  args=(stop,),           daemon=True, name="ingest_chat"),
        Thread(target=_ingest_media, args=(stop,),           daemon=True, name="ingest_media"),
    ]
    for i in range(QUEUE_NUM_WORKERS):
        threads.append(Thread(
            target=_worker_text, args=(i, cache, pg, stop),
            daemon=True, name=f"worker_text_{i}"
        ))
    for i in range(QUEUE_NUM_WORKERS):
        threads.append(Thread(
            target=_worker_media, args=(i, cache, pg, stop),
            daemon=True, name=f"worker_media_{i}"
        ))

    for th in threads:
        th.start()

    exec_log(
        f"DTA RUNNING — {QUEUE_NUM_WORKERS} workers texte + "
        f"{QUEUE_NUM_WORKERS} workers media — en attente d'evenements."
    )

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        exec_log("DTA STOP requested")
        stop.set()
        time.sleep(2.0)
        exec_log("DTA arrete proprement.")


if __name__ == "__main__":
    main()
