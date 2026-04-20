from __future__ import annotations

from config.settings import QUARANTINE_TRIGGER_ATTEMPTS
from ioevents.cache import ReferenceCache
from policy.actions import apply_hard_block, apply_quarantine, wazuh_alert
from utils.helpers import exec_log


def detect_media(cache: ReferenceCache, pg, ev) -> None:
    """
    Détection pour les événements image et audio.
    Comparaison du SHA256 contre le cache en mémoire (chargé depuis PostgreSQL).
    """
    user       = ev.username
    session_id = ev.session_id
    sha        = (ev.sha256 or "").lower()

    # Libérer un éventuel blocage expiré
    try:
        if pg.clear_expired_policy(user):
            exec_log(f"expired policy cleared for user={user}")
    except Exception as e:
        exec_log(f"clear_expired_policy error for user={user}: {repr(e)}")

    # Quarantine déjà active ?
    quarantined, until = pg.is_quarantine_active(user)
    if quarantined and until is not None:
        apply_quarantine(pg, user, session_id, until, {"reason": "already_quarantined"})
        return

    if ev.etype == "image" and sha and cache.is_sensitive_image(sha):
        _handle_sensitive_media(
            pg, user, session_id, sha, ev,
            media_kind="image",
            block_reason="Envoi bloqué : image sensible détectée.",
            wazuh_type="llm_leak_image",
        )
        return

    if ev.etype == "audio" and sha and cache.is_sensitive_audio(sha):
        _handle_sensitive_media(
            pg, user, session_id, sha, ev,
            media_kind="audio",
            block_reason="Envoi bloqué : audio sensible détecté.",
            wazuh_type="llm_leak_audio",
        )


# =========================
# Helper interne
# =========================

def _handle_sensitive_media(
    pg, user: str, session_id: str, sha: str, ev,
    media_kind: str, block_reason: str, wazuh_type: str,
) -> None:
    strike = pg.record_sensitive_attempt(user)

    if int(strike.get("strike_count") or 0) >= QUARANTINE_TRIGGER_ATTEMPTS:
        q = pg.activate_quarantine(user, "repeated_sensitive_attempts")
        apply_quarantine(pg, user, session_id, q["quarantine_until"], {
            "match_type": f"{media_kind}_sha256",
            "sha256":     sha[:12],
        })
        return

    apply_hard_block(
        pg, user, session_id,
        reason=block_reason,
        evidence={
            "match_type":    f"{media_kind}_sha256",
            "sha256_prefix": sha[:12],
            "filename":      ev.filename,
            "request_id":    ev.request_id,
        },
    )
    wazuh_alert(wazuh_type, {
        "policy_level": 2,
        "action":       "hard_block",
        "user":         user,
        "session_id":   session_id,
        "sha256_prefix": sha[:12],
    })
