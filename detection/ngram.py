"""
ngram.py — Moteur EDM (Exact Data Matching) par trigrammes + similarité Jaccard.

Ajout C4 : ngram_lookup_entities()
  Nouvelle fonction qui accepte une liste d'entités extraites par le LLM
  au lieu du texte complet, réduisant drastiquement les comparaisons DB.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Dict, List, Optional, Set

from utils.helpers import exec_log


# ══════════════════════════════════════════════════════════════
# SEUILS JACCARD
# ══════════════════════════════════════════════════════════════

JACCARD_WARN_THRESHOLD  = 0.40
JACCARD_BLOCK_THRESHOLD = 0.55
NGRAM_SIZE              = 3
MIN_COMMON_NGRAMS       = 2


# ══════════════════════════════════════════════════════════════
# NORMALISATION
# ══════════════════════════════════════════════════════════════

_LEET_TABLE = str.maketrans({
    '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
    '7': 't', '@': 'a', '$': 's', '!': 'i', '+': 't',
    '8': 'b', '6': 'g', '9': 'g',
})


def _normalize_for_ngram(text: str, skip_leet: bool = False) -> str:
    t = (text or "").strip()
    if not skip_leet:
        t = t.translate(_LEET_TABLE)
    t = unicodedata.normalize("NFKD", t)
    t = "".join(c for c in t if not unicodedata.combining(c))
    t = re.sub(r"[^a-zA-Z\s]", "", t)
    t = re.sub(r"\s+", " ", t).strip().lower()
    return t


# ══════════════════════════════════════════════════════════════
# GÉNÉRATION DES TRIGRAMMES
# ══════════════════════════════════════════════════════════════

def extract_ngrams(text: str, n: int = NGRAM_SIZE, skip_leet: bool = False) -> Set[str]:
    norm = _normalize_for_ngram(text, skip_leet=skip_leet)
    if not norm:
        return set()

    ngrams: Set[str] = set()

    for token in norm.split():
        if len(token) >= n:
            for i in range(len(token) - n + 1):
                ngrams.add(token[i:i + n])

    full = norm.replace(" ", "")
    if len(full) >= n:
        for i in range(len(full) - n + 1):
            ngrams.add(full[i:i + n])

    return ngrams


def ngrams_from_value(db_value: str, skip_leet: bool = False) -> Set[str]:
    return extract_ngrams(db_value, skip_leet=skip_leet)


# ══════════════════════════════════════════════════════════════
# SIMILARITÉ JACCARD
# ══════════════════════════════════════════════════════════════

def jaccard_similarity(set_a: Set[str], set_b: Set[str]) -> float:
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a & set_b)
    union        = len(set_a | set_b)
    return intersection / union if union > 0 else 0.0


# ══════════════════════════════════════════════════════════════
# INDEXATION
# ══════════════════════════════════════════════════════════════

def index_sensitive_value(pg, sensitive_id: int, label: str, value: str) -> int:
    ngrams = ngrams_from_value(value)
    if not ngrams:
        exec_log(f"index_sensitive_value: aucun trigramme pour '{value}'")
        return 0

    count = pg.upsert_ngrams(sensitive_id, label, ngrams)
    exec_log(
        f"index_sensitive_value: '{value}' → {count} trigrammes indexés "
        f"(label={label})"
    )
    return count


def reindex_all(pg) -> Dict[str, int]:
    exec_log("reindex_all: début de la réindexation complète")
    rows = pg.load_all_sensitive_text_with_id()

    total_values = 0
    total_ngrams = 0

    for row in rows:
        value = str(row["value"] or "").strip()
        label = str(row["label"] or "").strip()
        sid   = row["id"]

        if not value or sid is None:
            continue

        ngrams = ngrams_from_value(value, skip_leet=value.replace(" ", "").isdigit())
        if not ngrams:
            continue

        pg.upsert_ngrams(sid, label, ngrams)
        total_values += 1
        total_ngrams += len(ngrams)

    exec_log(
        f"reindex_all: {total_values} valeurs indexées, "
        f"{total_ngrams} trigrammes au total"
    )
    return {"total_values": total_values, "total_ngrams": total_ngrams}


# ══════════════════════════════════════════════════════════════
# DÉTECTION — ngram_lookup() original (texte complet)
# Conservé pour fallback si LLM indisponible
# ══════════════════════════════════════════════════════════════

def ngram_lookup(text: str, pg) -> Optional[Dict]:
    """
    Recherche EDM par trigrammes + Jaccard sur le texte complet.
    Utilisé en fallback quand le LLM est indisponible.
    """
    raw = (text or "").strip()
    if not raw:
        return None

    text_ngrams = extract_ngrams(raw)
    if not text_ngrams:
        return None

    try:
        db_entries = pg.load_all_ngrams()
    except Exception as e:
        exec_log(f"ngram_lookup: erreur DB: {repr(e)}")
        return None

    if not db_entries:
        exec_log("ngram_lookup: table sensitive_ngrams vide — lancer reindex_all()")
        return None

    return _find_best_match(text_ngrams, db_entries, source="texte_complet")


# ══════════════════════════════════════════════════════════════
# DÉTECTION C4 — ngram_lookup_entities() (entités LLM)
# NOUVEAU — opère sur 2-5 entités au lieu du texte complet
# ══════════════════════════════════════════════════════════════

def ngram_lookup_entities(entities: List[str], pg) -> Optional[Dict]:
    """
    C4 — Recherche EDM par trigrammes + Jaccard sur les entités extraites par le LLM.

    Au lieu de calculer les trigrammes du texte complet (5000 mots × 1M entrées DB),
    on calcule les trigrammes des 2-5 entités extraites seulement.

    Exemple :
      Texte original : "Bonjour, est-ce que Madame bouchar peut..."
      Entités LLM    : ["bouchar"]
      Trigrammes de "bouchar" : {"bou", "ouc", "uch", "cha", "har"}
      → Comparé uniquement aux entrées DB correspondantes
    """
    if not entities:
        return None

    try:
        db_entries = pg.load_all_ngrams()
    except Exception as e:
        exec_log(f"ngram_lookup_entities: erreur DB: {repr(e)}")
        return None

    if not db_entries:
        exec_log("ngram_lookup_entities: table sensitive_ngrams vide")
        return None

    best_match = None
    best_score = 0.0

    for entity in entities[:5]:
        entity_ngrams = extract_ngrams(entity)
        if not entity_ngrams:
            continue

        result = _find_best_match(entity_ngrams, db_entries, source=f"entité:{entity!r}")
        if result and result["jaccard"] > best_score:
            best_score = result["jaccard"]
            best_match = result

    return best_match


# ══════════════════════════════════════════════════════════════
# HELPERS INTERNES
# ══════════════════════════════════════════════════════════════

def _find_best_match(
    text_ngrams: Set[str],
    db_entries: List[Dict],
    source: str = "",
) -> Optional[Dict]:
    """
    Trouve le meilleur match Jaccard entre un ensemble de trigrammes
    et toutes les entrées de la DB.
    """
    best_match = None
    best_score = 0.0

    for entry in db_entries:
        db_value  = entry["value"]
        label     = entry["label"]
        db_ngrams = set(entry["ngrams"])

        if not db_ngrams:
            continue

        score        = jaccard_similarity(text_ngrams, db_ngrams)
        common_count = len(text_ngrams & db_ngrams)

        if common_count < MIN_COMMON_NGRAMS:
            continue

        if score > best_score:
            best_score = score
            best_match = {
                "matched_value": db_value,
                "label":         label,
                "score":         round(score * 100, 1),
                "jaccard":       score,
                "common_ngrams": common_count,
                "text_ngrams":   len(text_ngrams),
                "db_ngrams":     len(db_ngrams),
                "method":        "edm_jaccard",
                "source":        source,
            }

    if best_match and best_match["jaccard"] >= JACCARD_WARN_THRESHOLD:
        exec_log(
            f"ngram_lookup [{source}]: match EDM score={best_match['score']}% "
            f"label={best_match['label']} common={best_match['common_ngrams']}"
        )
        return best_match

    return None
