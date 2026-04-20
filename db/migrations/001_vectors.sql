-- ══════════════════════════════════════════════════════════════
-- Migration 001 — Ajout de la recherche vectorielle pgvector
-- À exécuter UNE SEULE FOIS sur le serveur PostgreSQL Ubuntu :
--   psql -U postgres -d postgres -f 001_vectors.sql
-- ══════════════════════════════════════════════════════════════

-- 1. Activer l'extension pgvector
CREATE EXTENSION IF NOT EXISTS vector;

-- 2. Ajouter la colonne embedding à la table existante sensitive_text
--    (384 dimensions = modèle paraphrase-multilingual-MiniLM-L12-v2)
ALTER TABLE public.sensitive_text
    ADD COLUMN IF NOT EXISTS embedding vector(384);

-- 3. Index de recherche approximative (HNSW) pour performances optimales
--    HNSW = Hierarchical Navigable Small World
--    Recherche O(log n) au lieu de O(n) — indispensable en production
CREATE INDEX IF NOT EXISTS idx_sensitive_text_embedding
    ON public.sensitive_text
    USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);

-- 4. Table de log des détections vectorielles (audit trail)
CREATE TABLE IF NOT EXISTS public.vector_detection_log (
    id              BIGSERIAL PRIMARY KEY,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    username        TEXT        NOT NULL,
    session_id      TEXT,
    request_id      TEXT,
    matched_label   TEXT        NOT NULL,
    similarity      FLOAT       NOT NULL,
    method          TEXT        NOT NULL,  -- 'vector', 'skeleton', 'direct'
    text_hash       TEXT        NOT NULL,  -- hash du texte (jamais le texte brut)
    action_taken    TEXT        NOT NULL   -- 'hard_block', 'quarantine', 'soft_block'
);

CREATE INDEX IF NOT EXISTS idx_vdl_username    ON public.vector_detection_log (username);
CREATE INDEX IF NOT EXISTS idx_vdl_detected_at ON public.vector_detection_log (detected_at DESC);

-- 5. Vue utile pour monitoring
CREATE OR REPLACE VIEW public.recent_detections AS
SELECT
    detected_at,
    username,
    matched_label,
    ROUND(similarity::numeric, 3) AS similarity,
    method,
    action_taken
FROM public.vector_detection_log
ORDER BY detected_at DESC
LIMIT 100;

COMMENT ON TABLE  public.vector_detection_log IS 'Audit trail des détections DLP vectorielles';
COMMENT ON COLUMN public.sensitive_text.embedding IS 'Vecteur 384d — modèle paraphrase-multilingual-MiniLM-L12-v2';
