"""
llm_filter.py - Filtre LLM local (C1 + C2)

Moteur : Ollama (port 11434) — gemma3:4b (3.3 GB)
Chat   : Ollama (port 11434) — llama3.1  (4.9 GB)

Pourquoi pas de contention :
  Le filtre est appele AVANT que le Backend envoie a Ollama chat.
  Sequence exacte :
    1. DTA recoit le message
    2. gemma3:4b analyse (filtre) → 2-5s
    3. Si sensible → blocage → Ollama chat ne recoit JAMAIS le message
    4. Si non sensible → Backend envoie a llama3.1 (chat)
  Les deux modeles ne sont jamais appeles simultanement.

Role :
  C1 — Classification : sensible ou non ?
  C2 — Extraction : quelles entites precises ?
"""
from __future__ import annotations

import json
import os
import time
from typing import Dict, List

import httpx

from utils.helpers import exec_log


# CONFIGURATION


OLLAMA_BASE_URL   = os.getenv("OLLAMA_BASE_URL",    "http://localhost:11434")
LLM_FILTER_MODEL  = os.getenv("LLM_FILTER_MODEL",   "gemma3:4b")
LLM_TIMEOUT_SEC   = float(os.getenv("LLM_FILTER_TIMEOUT", "25.0"))
MAX_ENTITIES      = 5

_SYSTEM_PROMPT = """/no_think
 Tu es un classificateur de securite DLP (Data Loss Prevention).

Ta tache : analyser un texte et detecter s'il contient des donnees personnelles sensibles.

Donnees sensibles a detecter :
- Noms de personnes (ex: "Bouchard", "Marie Tremblay", "bou char", "b.o.u.c.h.a.r")
- Numeros (telephone, NAS, carte bancaire, passeport, employe, client)
- Adresses email ou physiques
- Dates de naissance
- Toute donnee identifiable meme obfusquee (espaces inseres, points, leetspeak)

Reponds UNIQUEMENT avec un objet JSON valide, rien d'autre.

Si pas de donnees sensibles :
{"sensitive": false}

Si donnees sensibles detectees, liste les valeurs brutes extraites (max 5) :
{"sensitive": true, "entities": ["valeur1", "valeur2"]}

IMPORTANT :
- Reponds UNIQUEMENT avec le JSON, sans texte avant ou apres
- Pas de markdown, pas de backticks, pas d'explication
- Les entites doivent etre les valeurs telles qu'elles apparaissent dans le texte"""


def llm_classify_and_extract(text: str) -> Dict:
    """
    C1 — Classifie le prompt (sensible ou non)
    C2 — Extrait les entites si sensible

    Appelle Ollama /api/chat avec gemma3:4b
    """
    if not text or not text.strip():
        return {"sensitive": False}

    prompt_text = text[:2000].strip()

    # Format Ollama /api/chat
    payload = {
        "model": LLM_FILTER_MODEL,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user",   "content": prompt_text},
        ],
        "stream": False,
        "options": {
            "temperature": 0.0,
            "num_predict": 128,
        },
    }

    t0 = time.monotonic()
    try:
        with httpx.Client(timeout=LLM_TIMEOUT_SEC) as client:
            resp = client.post(
                f"{OLLAMA_BASE_URL}/api/chat",
                json=payload,
            )
            resp.raise_for_status()

        elapsed = round(time.monotonic() - t0, 3)
        raw     = resp.json()
        content = raw.get("message", {}).get("content", "").strip()

        exec_log(f"llm_filter: model={LLM_FILTER_MODEL} elapsed={elapsed}s raw={content[:120]!r}")

        result = _parse_llm_response(content)
        exec_log(f"llm_filter: sensitive={result['sensitive']} entities={result.get('entities', [])}")
        return result

    except httpx.TimeoutException:
        elapsed = round(time.monotonic() - t0, 3)
        exec_log(f"llm_filter: TIMEOUT apres {elapsed}s — pipeline fallback active")
        return {"sensitive": False, "error": "timeout", "fallback": True}

    except httpx.ConnectError:
        exec_log(f"llm_filter: Ollama inaccessible ({OLLAMA_BASE_URL}) — pipeline fallback")
        return {"sensitive": False, "error": "connect_error", "fallback": True}

    except Exception as e:
        exec_log(f"llm_filter: erreur inattendue: {repr(e)}")
        return {"sensitive": False, "error": repr(e), "fallback": True}


def _parse_llm_response(content: str) -> Dict:
    if not content:
        return {"sensitive": False, "error": "empty_response"}

    clean = content.strip()
    if clean.startswith("```"):
        lines = clean.split("\n")
        inner = [l for l in lines if not l.strip().startswith("```")]
        clean = "\n".join(inner).strip()

    start = clean.find("{")
    end   = clean.rfind("}") + 1
    if start >= 0 and end > start:
        clean = clean[start:end]

    try:
        data = json.loads(clean)
    except json.JSONDecodeError:
        exec_log(f"llm_filter: JSON invalide: {clean[:200]!r}")
        return {"sensitive": False, "error": "json_parse_error"}

    sensitive = bool(data.get("sensitive", False))
    if not sensitive:
        return {"sensitive": False}

    raw_entities = data.get("entities", [])
    if not isinstance(raw_entities, list):
        return {"sensitive": True, "entities": []}

    entities: List[str] = []
    for e in raw_entities[:MAX_ENTITIES]:
        val = str(e).strip()
        if val and len(val) >= 2:
            entities.append(val)

    return {"sensitive": True, "entities": entities}


def is_llm_available() -> bool:
    try:
        with httpx.Client(timeout=3.0) as client:
            r = client.get(f"{OLLAMA_BASE_URL}/api/tags")
            r.raise_for_status()
            models = r.json().get("models", [])
            names  = [m.get("name", "") for m in models]
            found  = any(LLM_FILTER_MODEL in n for n in names)
            exec_log(
                f"llm_filter: Ollama OK — modele '{LLM_FILTER_MODEL}' "
                f"{'TROUVE' if found else 'NON TROUVE'}"
            )
            return True
    except Exception as e:
        exec_log(f"llm_filter: Ollama non disponible: {repr(e)}")
        return False
