from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Optional

from config.settings import CUSTOM_ALERT_LOG, UI_DECISIONS_JSONL, HARD_BLOCK_MINUTES
from utils.helpers import now_iso, safe_json_append



# Alertes Wazuh


def wazuh_alert(event_type: str, details: dict) -> None:
    """Écrit une alerte dans le fichier Custom_alert.log (lu par Wazuh)."""
    payload = {
        "timestamp":  now_iso(),
        "type":       event_type,
        "canal":      "OLLAMA_CHAT",
        "details":    details,
    }
    safe_json_append(CUSTOM_ALERT_LOG, payload)


# Décisions UI


def ui_decision(
    user:       str,
    session_id: str,
    level:      int,
    action:     str,
    message:    str,
    evidence:   dict,
) -> None:
    """Écrit une décision dans ollama_dta_decisions.jsonl (consommé par le frontend)."""
    payload = {
        "ts":           now_iso(),
        "user":         user,
        "session_id":   session_id,
        "policy_level": level,
        "action":       action,
        "message":      message,
        "evidence":     evidence,
    }
    safe_json_append(UI_DECISIONS_JSONL, payload)


# Niveaux de blocage


def apply_soft_block(
    user: str, session_id: str, reason: str, evidence: dict
) -> None:
    """Niveau 1 — avertissement UI, aucune écriture en DB."""
    ui_decision(user, session_id, 1, "soft_block", reason, evidence)


def apply_hard_block(
    pg,
    user:       str,
    session_id: str,
    reason:     str,
    evidence:   dict,
) -> None:
    """Niveau 2 — blocage 60 min persisté en DB + alerte Wazuh."""
    ui_decision(user, session_id, 2, "hard_block", reason, evidence)
    blocked_until = datetime.now(timezone.utc) + timedelta(minutes=HARD_BLOCK_MINUTES)
    pg.upsert_policy(user, "hard_block", 2, blocked_until, reason)


def apply_quarantine(
    pg,
    user:       str,
    session_id: str,
    until_dt:   datetime,
    evidence:   dict,
) -> None:
    """Niveau 3 — quarantine persistée en DB + alerte Wazuh."""
    msg = (
        "Compte temporairement restreint (quarantine) "
        "suite à des tentatives répétées de fuite."
    )
    ui_decision(
        user, session_id, 3, "quarantine", msg,
        {**evidence, "quarantine_until": until_dt.isoformat()},
    )
    pg.upsert_policy(
        user, "quarantine", 3, until_dt,
        "repeated_sensitive_attempts",
        quarantine_until=until_dt,
    )
    wazuh_alert(
        "policy_quarantine",
        {
            "policy_level":     3,
            "action":           "quarantine",
            "user":             user,
            "session_id":       session_id,
            "quarantine_until": until_dt.isoformat(),
        },
    )
