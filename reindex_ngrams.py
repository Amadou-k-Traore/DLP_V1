#!/usr/bin/env python3
"""
reindex_ngrams.py — Script d'indexation initiale des trigrammes EDM.

À exécuter UNE SEULE FOIS après avoir appliqué la migration 002_ngrams.sql,
ou à relancer si tu ajoutes de nouvelles valeurs dans sensitive_text.

Usage :
  Windows : python reindex_ngrams.py
  Linux   : python3 reindex_ngrams.py
"""
import sys
import os

# Permet d'exécuter depuis n'importe où
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from db.store import PostgresStore
from detection.ngram import reindex_all, ngrams_from_value
from utils.helpers import exec_log


def main() -> None:
    print("=" * 60)
    print("DTA — Réindexation EDM (trigrammes + Jaccard)")
    print("=" * 60)

    pg = PostgresStore()

    # 1. Vérifier que la table sensitive_ngrams existe
    print("\n[1/4] Vérification de la table sensitive_ngrams...")
    try:
        exists = pg.check_ngrams_table()
        if not exists:
            print("  ❌ Table sensitive_ngrams INTROUVABLE.")
            print("     Applique d'abord la migration :")
            print("     psql -U dta_user -d postgres -f db/migrations/002_ngrams.sql")
            sys.exit(1)
        print("  ✅ Table sensitive_ngrams trouvée.")
    except Exception as e:
        print(f"  ❌ Erreur de connexion : {repr(e)}")
        sys.exit(1)

    # 2. Compter les valeurs sensibles à indexer
    print("\n[2/4] Chargement des valeurs sensibles...")
    try:
        rows = pg.load_all_sensitive_text_with_id()
        print(f"  ✅ {len(rows)} valeurs trouvées dans sensitive_text.")
    except Exception as e:
        print(f"  ❌ Erreur lecture sensitive_text : {repr(e)}")
        sys.exit(1)

    if not rows:
        print("  ⚠️  Aucune valeur sensible en DB. Rien à indexer.")
        sys.exit(0)

    # 3. Aperçu des trigrammes (pour vérification)
    print("\n[3/4] Aperçu des trigrammes (3 premières valeurs) :")
    for row in rows[:3]:
        value     = str(row["value"] or "")
        label     = str(row["label"] or "")
        skip_leet = value.replace(" ", "").isdigit()
        ngrams    = sorted(ngrams_from_value(value, skip_leet=skip_leet))
        print(f"  '{value}' (label={label})")
        print(f"    → {len(ngrams)} trigrammes : {ngrams[:10]}{'...' if len(ngrams) > 10 else ''}")

    # 4. Réindexation complète
    print(f"\n[4/4] Réindexation de {len(rows)} valeurs...")
    try:
        stats = reindex_all(pg)
        print(f"\n  ✅ Réindexation terminée !")
        print(f"     Valeurs indexées : {stats['total_values']}")
        print(f"     Trigrammes créés : {stats['total_ngrams']}")
        total_in_db = pg.count_ngrams()
        print(f"     Trigrammes en DB : {total_in_db}")
    except Exception as e:
        print(f"  ❌ Erreur réindexation : {repr(e)}")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("✅ Prêt. Le moteur EDM est actif au prochain démarrage du DTA.")
    print("=" * 60)


if __name__ == "__main__":
    main()
