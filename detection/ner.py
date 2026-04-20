from __future__ import annotations

import re
from typing import Dict, List, Set, Tuple

try:
    import spacy
except ImportError:
    spacy = None

from config.settings import (
    ENABLE_NER, SPACY_MODELS, MAX_TEXT_LEN, MAX_SEGMENTS_FOR_NER,
    COMMON_GPE, COMMON_ORG, COMMON_MISC,
    INTENT_PATTERNS,
)
from utils.helpers import exec_log, short_hash_text

_NLP = None


def get_nlp():
    """Charge le premier modèle spaCy disponible (singleton)."""
    global _NLP
    if not ENABLE_NER or spacy is None:
        return None
    if _NLP is None:
        for model in SPACY_MODELS:
            try:
                _NLP = spacy.load(model)
                exec_log(f"spaCy loaded: {model}")
                break
            except Exception as e:
                exec_log(f"spaCy load failed for {model}: {repr(e)}")
                _NLP = None
    return _NLP


# =========================
# Helpers internes
# =========================

def _normalize(s: str) -> str:
    return " ".join((s or "").strip().lower().split())


def _is_common(label: str, text: str) -> bool:
    norm = _normalize(text)
    if len(norm) < 3:
        return True
    if label in ("GPE", "LOC") and norm in COMMON_GPE:
        return True
    if label == "ORG" and norm in COMMON_ORG:
        return True
    if norm in COMMON_MISC:
        return True
    return False


def _intent_score(text: str) -> int:
    return sum(1 for rx in INTENT_PATTERNS if rx.search(text))


def _relevant_segments(text: str) -> List[str]:
    """Retourne les segments du texte qui contiennent au moins un signal d'intention."""
    raw = re.split(r"[\n\.!?;]+", text[:MAX_TEXT_LEN])
    segments = [s.strip() for s in raw if s.strip() and _intent_score(s.strip()) >= 1]
    if not segments:
        segments = [s.strip() for s in raw if s.strip()]
    return segments[:MAX_SEGMENTS_FOR_NER]


# =========================
# API publique
# =========================

def extract_entities(text: str) -> List[Dict[str, str]]:
    """
    Retourne les entités nommées non-communes trouvées dans le texte.
    Chaque entrée : {"label": str, "text": str, "text_hash": str}
    """
    nlp = get_nlp()
    if nlp is None or not text:
        return []

    found: List[Dict[str, str]] = []
    seen: Set[Tuple[str, str]] = set()

    for seg in _relevant_segments(text):
        try:
            doc = nlp(seg)
        except Exception as e:
            exec_log(f"spaCy inference failed: {repr(e)}")
            continue

        for ent in doc.ents:
            if ent.label_ not in ("PERSON", "ORG", "GPE", "LOC"):
                continue
            if _is_common(ent.label_, ent.text):
                continue
            key = (ent.label_, _normalize(ent.text))
            if key in seen:
                continue
            seen.add(key)
            found.append({
                "label":     ent.label_,
                "text":      ent.text.strip(),
                "text_hash": short_hash_text(ent.text.strip()),
            })

    return found
