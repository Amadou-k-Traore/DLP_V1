-- ══════════════════════════════════════════════════════════════
-- Migration 002 — Ajout de la détection EDM par trigrammes (Jaccard)
-- À exécuter UNE SEULE FOIS :
--   psql -U dta_user -d postgres -f 002_ngrams.sql
-- ══════════════════════════════════════════════════════════════

-- 1. Table des trigrammes indexés
--    Chaque ligne = un trigramme appartenant à une valeur sensible
CREATE TABLE IF NOT EXISTS public.sensitive_ngrams (
    id          BIGSERIAL    PRIMARY KEY,
    sensitive_id BIGINT      NOT NULL,          -- FK vers sensitive_text.id
    label       TEXT         NOT NULL,          -- copie du label pour éviter une jointure
    ngram       CHAR(3)      NOT NULL,          -- trigramme (3 caractères)
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- 2. Index pour la recherche rapide par trigramme
CREATE INDEX IF NOT EXISTS idx_sensitive_ngrams_ngram
    ON public.sensitive_ngrams (ngram);

-- 3. Index pour retrouver tous les trigrammes d'une valeur
CREATE INDEX IF NOT EXISTS idx_sensitive_ngrams_sensitive_id
    ON public.sensitive_ngrams (sensitive_id);

-- 4. Éviter les doublons (même valeur, même trigramme)
CREATE UNIQUE INDEX IF NOT EXISTS idx_sensitive_ngrams_uniq
    ON public.sensitive_ngrams (sensitive_id, ngram);

-- 5. Vue utile : compter les trigrammes par valeur sensible
CREATE OR REPLACE VIEW public.sensitive_ngrams_stats AS
SELECT
    sensitive_id,
    label,
    COUNT(*) AS ngram_count
FROM public.sensitive_ngrams
GROUP BY sensitive_id, label
ORDER BY ngram_count DESC;

COMMENT ON TABLE  public.sensitive_ngrams        IS 'Index EDM — trigrammes des valeurs sensibles pour recherche Jaccard';
COMMENT ON COLUMN public.sensitive_ngrams.ngram  IS 'Trigramme de 3 caractères extrait du squelette normalisé';
COMMENT ON COLUMN public.sensitive_ngrams.label  IS 'Label de la donnée sensible (copie dénormalisée pour perf)';
