"""
detection/text.py — Pipeline de détection texte (version améliorée C1-C4)
"""
from __future__ import annotations

import re
import unicodedata
from typing import Dict, List, Optional, Set

from rapidfuzz import fuzz

from config.settings import (
    MAX_TEXT_LEN, MAX_CANDIDATES_PER_TEXT,
    EMAIL_RE, LONG_NUM_RE, PHONE_RE, PASSPORT_RE, ID_TOKEN_RE,
    POTENTIAL_NAS_RE, POTENTIAL_DOB_RE,
    INTENT_PATTERNS, QUARANTINE_TRIGGER_ATTEMPTS,
    FUZZY_THRESHOLD,
)
from detection.ner import extract_entities
from detection.normalizer import (
    all_skeletons, db_skeleton_tokens, skeleton_tokens,
    COMMON_WORDS, best_match_score,
)
from detection.llm_filter import llm_classify_and_extract
from ioevents.cache import ReferenceCache
from policy.actions import (
    apply_soft_block, apply_hard_block, apply_quarantine, wazuh_alert,
)
from utils.helpers import exec_log, short_hash_text
from detection.ngram import (
    ngram_lookup,
    ngram_lookup_entities,
    JACCARD_WARN_THRESHOLD,
    JACCARD_BLOCK_THRESHOLD,
)

FREE_TEXT_BLOCK_THRESHOLD = 92
FREE_TEXT_WARN_THRESHOLD  = 86
SKELETON_THRESHOLD        = 78


def _strip_accents(s: str) -> str:
    return "".join(
        c for c in unicodedata.normalize("NFKD", s)
        if not unicodedata.combining(c)
    )


def _normalize_free_text(s: str) -> str:
    s = (s or "").strip().lower()
    s = _strip_accents(s)
    s = re.sub(r"[_\-.]+", " ", s)
    s = re.sub(r"[^\w\s]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _compute_scores(a: str, b: str) -> Dict[str, float]:
    return {
        "ratio":            fuzz.ratio(a, b),
        "partial_ratio":    fuzz.partial_ratio(a, b),
        "token_sort_ratio": fuzz.token_sort_ratio(a, b),
        "token_set_ratio":  fuzz.token_set_ratio(a, b),
    }


def _best_score(scores: Dict[str, float]) -> float:
    return max(scores.values()) if scores else 0.0


_WORD_RE = re.compile(r"\b[a-zA-ZÀ-ÿ]{4,}\b")


def _is_valid_id_token(value: str) -> bool:
    return (
        len(value) >= 5
        and any(c.isalpha() for c in value)
        and any(c.isdigit() for c in value)
    )


def extract_candidates(text: str) -> List[str]:
    if not text:
        return []
    work = text[:MAX_TEXT_LEN]
    candidates: Set[str] = set()

    for rx in (EMAIL_RE, LONG_NUM_RE, PHONE_RE, PASSPORT_RE):
        for m in rx.finditer(work):
            if v := m.group(0).strip():
                candidates.add(v)
            if len(candidates) >= MAX_CANDIDATES_PER_TEXT:
                return list(candidates)

    for m in ID_TOKEN_RE.finditer(work):
        if (v := m.group(0).strip()) and _is_valid_id_token(v):
            candidates.add(v)
        if len(candidates) >= MAX_CANDIDATES_PER_TEXT:
            return list(candidates)

    for m in _WORD_RE.finditer(work):
        v = m.group(0).strip()
        if v and v.lower() not in COMMON_WORDS:
            candidates.add(v)
        if len(candidates) >= MAX_CANDIDATES_PER_TEXT:
            return list(candidates)

    return list(candidates)


def intent_score(text: str) -> int:
    if not text:
        return 0
    return sum(1 for rx in INTENT_PATTERNS if rx.search(text[:MAX_TEXT_LEN]))


def free_text_lookup(text: str, pg, entities: Optional[List[str]] = None) -> Optional[Dict]:
    if entities:
        texts_to_check = entities[:5]
        exec_log(f"free_text_lookup: mode ENTITES LLM ({len(texts_to_check)} entites)")
    else:
        raw = (text or "")[:MAX_TEXT_LEN]
        if not raw.strip():
            return None
        texts_to_check = [raw]
        exec_log("free_text_lookup: mode TEXTE COMPLET (fallback)")

    try:
        rows = pg.load_all_sensitive_text()
    except Exception as e:
        exec_log(f"free_text_lookup: erreur DB: {repr(e)}")
        return None

    if not rows:
        return None

    best_match = None
    best_sc    = 0.0

    for candidate_text in texts_to_check:
        norm_candidate = _normalize_free_text(candidate_text)
        if not norm_candidate:
            continue

        for row in rows:
            db_val = str(row["value"] or "").strip()
            label  = str(row["label"] or "").strip()
            if not db_val:
                continue

            norm_db = _normalize_free_text(db_val)
            if not norm_db:
                continue

            scores     = _compute_scores(norm_candidate, norm_db)
            best_local = _best_score(scores)

            if norm_db in norm_candidate:
                best_local = max(best_local, 100.0)

            if best_local > best_sc:
                best_sc    = best_local
                best_match = {
                    "matched_value": db_val,
                    "label":         label,
                    "score":         best_local,
                    "scores":        scores,
                    "method":        "free_text_fuzzy",
                    "candidate":     candidate_text,
                }

    if best_match and best_match["score"] >= FREE_TEXT_WARN_THRESHOLD:
        return best_match

    return None


def skeleton_lookup(text: str, pg) -> Optional[Dict]:
    try:
        rows = pg.load_all_sensitive_text()
    except Exception as e:
        exec_log(f"skeleton_lookup: erreur DB: {repr(e)}")
        return None

    if not rows:
        return None

    text_skels = all_skeletons(text)
    if not text_skels:
        return None

    best_match = None
    best_sc    = 0

    for row in rows:
        db_val = str(row["value"] or "")
        label  = str(row["label"] or "")

        # Ignorer les valeurs trop courtes — trop de faux positifs
        if len(db_val.strip()) < 7:
            continue

        db_skels = db_skeleton_tokens(db_val.lower())
        if not db_skels:
            continue

        token_scores = [
            max((best_match_score(txt_sk, db_sk) for txt_sk in text_skels), default=0)
            for db_sk in db_skels
        ]
        global_score = round(sum(token_scores) / len(token_scores))

        if global_score >= SKELETON_THRESHOLD and global_score > best_sc:
            best_sc    = global_score
            best_match = {
                "matched_value": db_val,
                "label":         label,
                "score":         global_score,
                "method":        "skeleton",
            }

    return best_match


def detect_text(cache: ReferenceCache, pg, ev) -> None:
    text = (ev.text or "")[:MAX_TEXT_LEN]
    if not text.strip():
        return

    user       = ev.username
    session_id = ev.session_id
    text_hash  = short_hash_text(text)

    exec_log(f"detect_text: user={user} hash={text_hash}")

    try:
        if pg.clear_expired_policy(user):
            exec_log(f"expired policy cleared for user={user}")
    except Exception as e:
        exec_log(f"clear_expired_policy error: {repr(e)}")

    quarantined, until = pg.is_quarantine_active(user)
    if quarantined and until is not None:
        apply_quarantine(pg, user, session_id, until, {"reason": "already_quarantined"})
        return

    score    = intent_score(text)
    entities = extract_entities(text)

    # C1+C2 — FILTRE LLM
    llm_result   = llm_classify_and_extract(text)
    llm_error    = llm_result.get("error")
    llm_fallback = llm_result.get("fallback", False)

    if llm_error and not llm_fallback:
        exec_log(f"llm_filter: erreur non-fatale {llm_error!r} — pipeline continue")

    if not llm_result.get("sensitive", False) and not llm_fallback:
        exec_log(f"llm_filter: NON sensible — prompt autorise sans DB (user={user})")
        return

    llm_entities: List[str] = llm_result.get("entities", [])

    if llm_fallback:
        exec_log(f"llm_filter: FALLBACK actif (Ollama indisponible) — pipeline complet")
        llm_entities = []
    else:
        exec_log(f"llm_filter: OUI sensible — entites={llm_entities} (user={user})")

    use_entities = llm_entities if llm_entities else None

    # NIVEAU 1 — FUZZY
    match = free_text_lookup(text, pg, entities=use_entities)

    if match:
        label  = match["label"]
        sim    = match["score"]
        method = match["method"]

        exec_log(
            f"FREE_TEXT DETECTION user={user} score={sim:.1f}% "
            f"label={label} method={method} candidate={match.get('candidate', '')!r}"
        )

        if sim >= FREE_TEXT_BLOCK_THRESHOLD:
            strike = pg.record_sensitive_attempt(user)
            if int(strike.get("strike_count") or 0) >= QUARANTINE_TRIGGER_ATTEMPTS:
                q = pg.activate_quarantine(user, "repeated_sensitive_attempts")
                apply_quarantine(pg, user, session_id, q["quarantine_until"], {
                    "match_type":   method,
                    "label":        label,
                    "similarity":   round(sim, 1),
                    "request_id":   ev.request_id,
                    "llm_entities": llm_entities,
                })
                return

            apply_hard_block(
                pg, user, session_id,
                reason="Envoi bloque : donnee sensible detectee.",
                evidence={
                    "match_type":   method,
                    "label":        label,
                    "similarity":   round(sim, 1),
                    "request_id":   ev.request_id,
                    "intent_score": score,
                    "ner_count":    len(entities),
                    "llm_entities": llm_entities,
                },
            )
            wazuh_alert("llm_leak_text", {
                "policy_level": 2,
                "action":       "hard_block",
                "user":         user,
                "session_id":   session_id,
                "label":        label,
                "similarity":   round(sim, 1),
                "method":       method,
                "text_hash":    text_hash,
                "llm_filter":   "hit",
                "llm_entities": llm_entities,
            })
            return

        else:
            apply_soft_block(
                user, session_id,
                reason="Contenu potentiellement sensible detecte.",
                evidence={
                    "match_type":   method,
                    "label":        label,
                    "similarity":   round(sim, 1),
                    "request_id":   ev.request_id,
                    "llm_entities": llm_entities,
                },
            )
            return

    # NIVEAU 1.5 — JACCARD
    if use_entities:
        match = ngram_lookup_entities(use_entities, pg)
    else:
        match = ngram_lookup(text, pg)

    if match:
        label  = match["label"]
        sim    = match["score"]
        method = match["method"]

        exec_log(
            f"EDM JACCARD DETECTION user={user} score={sim}% "
            f"label={label} common_ngrams={match['common_ngrams']}"
        )

        if match["jaccard"] >= JACCARD_BLOCK_THRESHOLD:
            strike = pg.record_sensitive_attempt(user)
            if int(strike.get("strike_count") or 0) >= QUARANTINE_TRIGGER_ATTEMPTS:
                q = pg.activate_quarantine(user, "repeated_sensitive_attempts")
                apply_quarantine(pg, user, session_id, q["quarantine_until"], {
                    "match_type": method,
                    "label":      label,
                    "similarity": round(sim, 1),
                    "request_id": ev.request_id,
                })
                return

            apply_hard_block(
                pg, user, session_id,
                reason="Envoi bloque : donnee sensible detectee (EDM).",
                evidence={
                    "match_type":    method,
                    "label":         label,
                    "similarity":    round(sim, 1),
                    "common_ngrams": match["common_ngrams"],
                    "request_id":    ev.request_id,
                    "intent_score":  score,
                    "ner_count":     len(entities),
                    "llm_entities":  llm_entities,
                },
            )
            wazuh_alert("llm_leak_text", {
                "policy_level": 2,
                "action":       "hard_block",
                "user":         user,
                "session_id":   session_id,
                "label":        label,
                "similarity":   round(sim, 1),
                "method":       method,
                "text_hash":    text_hash,
                "llm_filter":   "hit",
                "llm_entities": llm_entities,
            })
            return

        else:
            apply_soft_block(
                user, session_id,
                reason="Contenu potentiellement sensible detecte (EDM).",
                evidence={
                    "match_type":    method,
                    "label":         label,
                    "similarity":    round(sim, 1),
                    "common_ngrams": match["common_ngrams"],
                    "request_id":    ev.request_id,
                    "llm_entities":  llm_entities,
                },
            )
            return

    # NIVEAU 2 — SQUELETTE
    match = skeleton_lookup(text, pg)

    if match:
        label  = match["label"]
        sim    = match["score"]
        method = match["method"]

        exec_log(
            f"SKELETON DETECTION user={user} score={sim}% "
            f"label={label} method={method}"
        )

        strike = pg.record_sensitive_attempt(user)
        if int(strike.get("strike_count") or 0) >= QUARANTINE_TRIGGER_ATTEMPTS:
            q = pg.activate_quarantine(user, "repeated_sensitive_attempts")
            apply_quarantine(pg, user, session_id, q["quarantine_until"], {
                "match_type": method,
                "label":      label,
                "similarity": sim,
                "request_id": ev.request_id,
            })
            return

        apply_hard_block(
            pg, user, session_id,
            reason="Envoi bloque : donnee sensible detectee (contournement).",
            evidence={
                "match_type":   method,
                "label":        label,
                "similarity":   sim,
                "request_id":   ev.request_id,
                "intent_score": score,
                "ner_count":    len(entities),
            },
        )
        wazuh_alert("llm_leak_text", {
            "policy_level": 2,
            "action":       "hard_block",
            "user":         user,
            "session_id":   session_id,
            "label":        label,
            "similarity":   sim,
            "method":       method,
            "text_hash":    text_hash,
        })
        return

    # NIVEAU 3 — INTENT + NER
    if score >= 2:
        apply_soft_block(
            user, session_id,
            reason="Intention potentielle d'extraction de donnees sensibles.",
            evidence={
                "match_type":   "intent",
                "intent_score": score,
                "request_id":   ev.request_id,
                "ner_count":    len(entities),
                "entities":     entities[:10],
            },
        )
        return

    if len(entities) >= 2 and score >= 1:
        apply_soft_block(
            user, session_id,
            reason="Plusieurs entites potentiellement sensibles detectees.",
            evidence={
                "match_type":   "ner_context",
                "request_id":   ev.request_id,
                "intent_score": score,
                "ner_count":    len(entities),
                "entities":     entities[:10],
            },
        )
        return

    if POTENTIAL_NAS_RE.search(text) or POTENTIAL_DOB_RE.search(text):
        apply_soft_block(
            user, session_id,
            reason="Contenu potentiellement sensible (NAS ou date de naissance).",
            evidence={
                "match_type":   "text_potential",
                "request_id":   ev.request_id,
                "intent_score": score,
                "ner_count":    len(entities),
            },
        )
