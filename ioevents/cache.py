from __future__ import annotations

from threading import Lock
from typing import Dict, List, Set


class ReferenceCache:
    """Cache en mémoire des SHA256 de médias sensibles, rechargé périodiquement."""

    def __init__(self) -> None:
        self._lock      = Lock()
        self.image_sha: Set[str] = set()
        self.audio_sha: Set[str] = set()

    def rebuild(self, media_rows: List[Dict]) -> None:
        """Reconstruit le cache à partir des lignes PostgreSQL."""
        img: Set[str] = set()
        aud: Set[str] = set()

        for r in media_rows:
            mtype = str(r.get("media_type") or "").strip().lower()
            sh    = str(r.get("sha256")     or "").strip().lower()
            if not sh:
                continue
            if mtype == "image":
                img.add(sh)
            elif mtype == "audio":
                aud.add(sh)

        with self._lock:
            self.image_sha = img
            self.audio_sha = aud

    def is_sensitive_image(self, sha: str) -> bool:
        sha = (sha or "").lower()
        with self._lock:
            return bool(sha) and sha in self.image_sha

    def is_sensitive_audio(self, sha: str) -> bool:
        sha = (sha or "").lower()
        with self._lock:
            return bool(sha) and sha in self.audio_sha
