from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    print("psycopg non installé. Installe: pip install psycopg[binary]")
    raise

from config.settings import (
    PG_HOST, PG_PORT, PG_DB, PG_USER, PG_PASS,
    QUARANTINE_WINDOW_MIN, QUARANTINE_DURATION_MIN,
)


class PostgresStore:
    """Accès PostgreSQL : lecture des références et gestion des politiques utilisateur."""

    def __init__(self) -> None:
        self.dsn = (
            f"host={PG_HOST} port={PG_PORT} dbname={PG_DB} "
            f"user={PG_USER} password={PG_PASS}"
        )

    def connect(self):
        return psycopg.connect(self.dsn, row_factory=dict_row, connect_timeout=5)

    # ------------------------------------------------------------------
    # Diagnostic
    # ------------------------------------------------------------------

    def ping(self) -> Dict:
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT current_database() AS db, inet_server_addr() AS server_ip;"
                )
                return cur.fetchone()

    def check_tables(self) -> Dict:
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                      to_regclass('public.sensitive_text')       AS sensitive_text,
                      to_regclass('public.sensitive_media')      AS sensitive_media,
                      to_regclass('public.user_policy')          AS user_policy,
                      to_regclass('public.vector_detection_log') AS vector_detection_log;
                    """
                )
                return cur.fetchone()

    # ------------------------------------------------------------------
    # Références sensibles — médias
    # ------------------------------------------------------------------

    def load_sensitive_media(self) -> List[Dict]:
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT media_type, sha256, label FROM public.sensitive_media"
                )
                return cur.fetchall()

    # ------------------------------------------------------------------
    # Références sensibles — texte
    # ------------------------------------------------------------------

    def load_all_sensitive_text(self) -> List[Dict]:
        """
        Charge TOUTES les valeurs de sensitive_text pour le fuzzy matching en mémoire.
        Utilisé par fuzzy_lookup_sensitive() et fuzzy_lookup_fulltext() dans detection/text.py.
        """
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT value, label FROM public.sensitive_text")
                return cur.fetchall()

    def lookup_sensitive_candidates(self, values: List[str]) -> Dict[str, str]:
        """Batch-lookup exact : renvoie {value: label} pour les valeurs présentes en DB.
        Conservé pour compatibilité, mais remplacé par fuzzy_lookup_* dans le pipeline principal.
        """
        if not values:
            return {}
        uniq = list(dict.fromkeys(values))
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT value, label FROM public.sensitive_text WHERE value = ANY(%s)",
                    (uniq,),
                )
                rows = cur.fetchall()
        return {str(r["value"]): str(r["label"]) for r in rows}

    def count_sensitive_text(self) -> int:
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS n FROM public.sensitive_text")
                row = cur.fetchone()
                return int(row["n"] if row else 0)

    # ------------------------------------------------------------------
    # Politique utilisateur
    # ------------------------------------------------------------------

    def upsert_policy(
        self,
        username:         str,
        action:           str,
        level:            int,
        blocked_until:    Optional[datetime],
        reason:           str,
        quarantine_until: Optional[datetime] = None,
    ) -> None:
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO public.user_policy
                        (username, action, policy_level, blocked_until, quarantine_until, reason, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (username) DO UPDATE SET
                        action          = EXCLUDED.action,
                        policy_level    = EXCLUDED.policy_level,
                        blocked_until   = EXCLUDED.blocked_until,
                        quarantine_until = EXCLUDED.quarantine_until,
                        reason          = EXCLUDED.reason,
                        updated_at      = NOW()
                    """,
                    (username, action, level, blocked_until, quarantine_until, reason),
                )
            conn.commit()

    def clear_expired_policy(self, username: str) -> bool:
        """Réinitialise la politique si le blocage/quarantine a expiré. Retourne True si mis à jour."""
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE public.user_policy
                    SET action='allow', policy_level=0,
                        blocked_until=NULL, quarantine_until=NULL,
                        strike_count=0, first_strike_at=NULL,
                        reason=NULL, updated_at=NOW()
                    WHERE username=%s
                      AND (
                            (blocked_until   IS NOT NULL AND blocked_until   <= NOW())
                         OR (quarantine_until IS NOT NULL AND quarantine_until <= NOW())
                      )
                      AND action IN ('hard_block', 'quarantine')
                    """,
                    (username,),
                )
                updated = cur.rowcount > 0
            conn.commit()
        return updated

    def is_quarantine_active(self, username: str) -> Tuple[bool, Optional[datetime]]:
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT quarantine_until
                    FROM public.user_policy
                    WHERE username=%s
                      AND action='quarantine'
                      AND quarantine_until IS NOT NULL
                      AND quarantine_until > NOW()
                    """,
                    (username,),
                )
                row = cur.fetchone()
        if not row:
            return (False, None)
        return (True, row["quarantine_until"])

    def record_sensitive_attempt(self, username: str) -> Dict:
        """Incrémente le compteur de strikes dans la fenêtre glissante."""
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO public.user_policy
                        (username, action, policy_level, strike_count, first_strike_at, updated_at)
                    VALUES (%s, 'allow', 0, 1, NOW(), NOW())
                    ON CONFLICT (username) DO UPDATE SET
                        strike_count = CASE
                            WHEN public.user_policy.first_strike_at IS NULL
                              OR public.user_policy.first_strike_at < NOW() - (%s || ' minutes')::interval
                            THEN 1
                            ELSE public.user_policy.strike_count + 1
                        END,
                        first_strike_at = CASE
                            WHEN public.user_policy.first_strike_at IS NULL
                              OR public.user_policy.first_strike_at < NOW() - (%s || ' minutes')::interval
                            THEN NOW()
                            ELSE public.user_policy.first_strike_at
                        END,
                        updated_at = NOW()
                    RETURNING username, strike_count, first_strike_at
                    """,
                    (username, QUARANTINE_WINDOW_MIN, QUARANTINE_WINDOW_MIN),
                )
                row = cur.fetchone()
            conn.commit()
        return row

    def activate_quarantine(self, username: str, reason: str) -> Dict:
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO public.user_policy
                        (username, action, policy_level, blocked_until, quarantine_until, reason, updated_at)
                    VALUES
                        (%s, 'quarantine', 3,
                         NOW() + (%s || ' minutes')::interval,
                         NOW() + (%s || ' minutes')::interval,
                         %s, NOW())
                    ON CONFLICT (username) DO UPDATE SET
                        action          = 'quarantine',
                        policy_level    = 3,
                        blocked_until   = NOW() + (%s || ' minutes')::interval,
                        quarantine_until = NOW() + (%s || ' minutes')::interval,
                        reason          = EXCLUDED.reason,
                        updated_at      = NOW()
                    RETURNING username, action, policy_level, blocked_until, quarantine_until, reason
                    """,
                    (
                        username,
                        QUARANTINE_DURATION_MIN, QUARANTINE_DURATION_MIN,
                        reason,
                        QUARANTINE_DURATION_MIN, QUARANTINE_DURATION_MIN,
                    ),
                )
                row = cur.fetchone()
            conn.commit()
        return row

    # ------------------------------------------------------------------
    # Politique utilisateur
    # ------------------------------------------------------------------

    def upsert_policy(
        self,
        username:         str,
        action:           str,
        level:            int,
        blocked_until:    Optional[datetime],
        reason:           str,
        quarantine_until: Optional[datetime] = None,
    ) -> None:
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO public.user_policy
                        (username, action, policy_level, blocked_until, quarantine_until, reason, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (username) DO UPDATE SET
                        action          = EXCLUDED.action,
                        policy_level    = EXCLUDED.policy_level,
                        blocked_until   = EXCLUDED.blocked_until,
                        quarantine_until = EXCLUDED.quarantine_until,
                        reason          = EXCLUDED.reason,
                        updated_at      = NOW()
                    """,
                    (username, action, level, blocked_until, quarantine_until, reason),
                )
            conn.commit()

    def clear_expired_policy(self, username: str) -> bool:
        """Réinitialise la politique si le blocage/quarantine a expiré. Retourne True si mis à jour."""
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE public.user_policy
                    SET action='allow', policy_level=0,
                        blocked_until=NULL, quarantine_until=NULL,
                        strike_count=0, first_strike_at=NULL,
                        reason=NULL, updated_at=NOW()
                    WHERE username=%s
                      AND (
                            (blocked_until   IS NOT NULL AND blocked_until   <= NOW())
                         OR (quarantine_until IS NOT NULL AND quarantine_until <= NOW())
                      )
                      AND action IN ('hard_block', 'quarantine')
                    """,
                    (username,),
                )
                updated = cur.rowcount > 0
            conn.commit()
        return updated

    def is_quarantine_active(self, username: str) -> Tuple[bool, Optional[datetime]]:
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT quarantine_until
                    FROM public.user_policy
                    WHERE username=%s
                      AND action='quarantine'
                      AND quarantine_until IS NOT NULL
                      AND quarantine_until > NOW()
                    """,
                    (username,),
                )
                row = cur.fetchone()
        if not row:
            return (False, None)
        return (True, row["quarantine_until"])

    def record_sensitive_attempt(self, username: str) -> Dict:
        """Incrémente le compteur de strikes dans la fenêtre glissante."""
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO public.user_policy
                        (username, action, policy_level, strike_count, first_strike_at, updated_at)
                    VALUES (%s, 'allow', 0, 1, NOW(), NOW())
                    ON CONFLICT (username) DO UPDATE SET
                        strike_count = CASE
                            WHEN public.user_policy.first_strike_at IS NULL
                              OR public.user_policy.first_strike_at < NOW() - (%s || ' minutes')::interval
                            THEN 1
                            ELSE public.user_policy.strike_count + 1
                        END,
                        first_strike_at = CASE
                            WHEN public.user_policy.first_strike_at IS NULL
                              OR public.user_policy.first_strike_at < NOW() - (%s || ' minutes')::interval
                            THEN NOW()
                            ELSE public.user_policy.first_strike_at
                        END,
                        updated_at = NOW()
                    RETURNING username, strike_count, first_strike_at
                    """,
                    (username, QUARANTINE_WINDOW_MIN, QUARANTINE_WINDOW_MIN),
                )
                row = cur.fetchone()
            conn.commit()
        return row

    def activate_quarantine(self, username: str, reason: str) -> Dict:
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO public.user_policy
                        (username, action, policy_level, blocked_until, quarantine_until, reason, updated_at)
                    VALUES
                        (%s, 'quarantine', 3,
                         NOW() + (%s || ' minutes')::interval,
                         NOW() + (%s || ' minutes')::interval,
                         %s, NOW())
                    ON CONFLICT (username) DO UPDATE SET
                        action          = 'quarantine',
                        policy_level    = 3,
                        blocked_until   = NOW() + (%s || ' minutes')::interval,
                        quarantine_until = NOW() + (%s || ' minutes')::interval,
                        reason          = EXCLUDED.reason,
                        updated_at      = NOW()
                    RETURNING username, action, policy_level, blocked_until, quarantine_until, reason
                    """,
                    (
                        username,
                        QUARANTINE_DURATION_MIN, QUARANTINE_DURATION_MIN,
                        reason,
                        QUARANTINE_DURATION_MIN, QUARANTINE_DURATION_MIN,
                    ),
                )
                row = cur.fetchone()
            conn.commit()
        return row

    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    # EDM — Trigrammes (sensitive_ngrams)
    # À ajouter dans la classe PostgresStore, après count_sensitive_text()
    # ------------------------------------------------------------------

    def load_all_ngrams(self) -> List[Dict]:
        """
        Charge tous les trigrammes groupés par valeur sensible.

        Retourne une liste de dicts :
          [
            {
              "sensitive_id": 1,
              "value": "juillien bouchar",
              "label": "client_001",
              "ngrams": ["jui", "uil", "ill", ...]
            },
            ...
          ]
        """
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        n.sensitive_id,
                        t.value,
                        n.label,
                        array_agg(n.ngram) AS ngrams
                    FROM public.sensitive_ngrams n
                    JOIN public.sensitive_text t ON t.id = n.sensitive_id
                    GROUP BY n.sensitive_id, t.value, n.label
                    """
                )
                return cur.fetchall()

    def upsert_ngrams(
        self,
        sensitive_id: int,
        label: str,
        ngrams: set,
    ) -> int:
        """
        Insère ou met à jour les trigrammes d'une valeur sensible.
        Utilise ON CONFLICT DO NOTHING pour éviter les doublons.

        Retourne le nombre de trigrammes insérés.
        """
        if not ngrams:
            return 0

        rows = [(sensitive_id, label, ng) for ng in ngrams]

        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.executemany(
                    """
                    INSERT INTO public.sensitive_ngrams (sensitive_id, label, ngram)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (sensitive_id, ngram) DO NOTHING
                    """,
                    rows,
                )
                inserted = cur.rowcount
            conn.commit()
        return inserted

    def delete_ngrams(self, sensitive_id: int) -> int:
        """
        Supprime tous les trigrammes d'une valeur sensible.
        À appeler avant une réindexation ou lors d'une suppression.
        """
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM public.sensitive_ngrams WHERE sensitive_id = %s",
                    (sensitive_id,),
                )
                deleted = cur.rowcount
            conn.commit()
        return deleted

    def count_ngrams(self) -> int:
        """Retourne le nombre total de trigrammes indexés."""
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS n FROM public.sensitive_ngrams")
                row = cur.fetchone()
                return int(row["n"] if row else 0)

    def load_all_sensitive_text_with_id(self) -> List[Dict]:
        """
        Comme load_all_sensitive_text() mais inclut l'id.
        Nécessaire pour l'indexation des trigrammes.
        """
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, value, label FROM public.sensitive_text")
                return cur.fetchall()

    def check_ngrams_table(self) -> bool:
        """Vérifie si la table sensitive_ngrams existe."""
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT to_regclass('public.sensitive_ngrams') AS t"
                )
                row = cur.fetchone()
                return row["t"] is not None
