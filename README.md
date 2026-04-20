# DTA — Data Threat Analyzer

Système DLP temps réel pour la protection des données sensibles.
Déployé sur serveur centralisé — les postes n'ont besoin que d'un navigateur.

## Structure

```
dta/
├── main.py                  # Point d'entrée, orchestration des threads + Queue
├── requirements.txt         # Dépendances Python
├── config/
│   └── settings.py          # Constantes, variables d'env, regex, FUZZY_THRESHOLD
├── db/
│   └── store.py             # PostgresStore — toutes les requêtes SQL
├── detection/
│   ├── text.py              # Pipeline texte : fuzzy matching noms/tokens + intent + NER
│   ├── media.py             # Pipeline image/audio : SHA256 lookup
│   └── ner.py               # Chargement spaCy, extract_entities()
├── policy/
│   └── actions.py           # soft_block, hard_block, quarantine, wazuh_alert
├── io/
│   ├── events.py            # LogEvent, parse_event(), tail_jsonl()
│   └── cache.py             # ReferenceCache (SHA256 en mémoire)
└── utils/
    └── helpers.py           # hash, filesystem, logging interne
```

## Installation

```bash
# 1. Installer les dépendances
pip install -r requirements.txt

# 2. Installer les modèles spaCy
python -m spacy download fr_core_news_sm
python -m spacy download en_core_web_sm

# 3. Définir la variable d'environnement du mot de passe PostgreSQL
# Windows :
setx PG_PASS "votre_mot_de_passe"
# Linux :
export PG_PASS="votre_mot_de_passe"

# 4. Lancer le DTA
python main.py
```

## Variables d'environnement

| Variable           | Obligatoire | Défaut                        |
|--------------------|-------------|-------------------------------|
| PG_PASS            | ✅ Oui      | —                             |
| PG_HOST            | Non         | 10.22.1.69                    |
| PG_PORT            | Non         | 5432                          |
| PG_DB              | Non         | postgres                      |
| PG_USER            | Non         | dta_user                      |
| CHAT_LOG_JSONL     | Non         | logs/chat_input.jsonl         |
| MEDIA_LOG_JSONL    | Non         | logs/media_uploads.jsonl      |
| CUSTOM_ALERT_LOG   | Non         | logs/Custom_alert.log         |
| UI_DECISIONS_JSONL | Non         | logs/ollama_dta_decisions.jsonl|
| DTA_EXEC_LOG       | Non         | logs/dta_exec.log             |

## Améliorations appliquées

| # | Description                                        | Fichier(s)                      |
|---|----------------------------------------------------|---------------------------------|
| 1 | Mot de passe via variable d'env                    | config/settings.py              |
| 2 | Log démarrage/arrêt de chaque thread               | main.py                         |
| 3 | NER + intent combinés (réduction faux positifs)    | detection/text.py               |
| 4 | requirements.txt                                   | requirements.txt                |
| 5 | Queue asynchrone (serveur centralisé)              | main.py + settings.py           |
| 6 | **Détection noms propres (Julien, Bouchard...)**   | detection/text.py + db/store.py |
|   | - `_NAME_RE` : extrait mots avec majuscule initiale|                                 |
|   | - `_is_valid_id_token` corrigé (accepte noms purs) |                                 |
|   | - `fuzzy_lookup_sensitive` : partial_ratio par token|                                |
|   | - `fuzzy_lookup_fulltext` : token_set_ratio sur la phrase complète | |
|   | - `load_all_sensitive_text()` dans PostgresStore   |                                 |

## Comment fonctionne la détection des noms (correction #6)

### Avant (ne marchait pas)
- `_is_valid_id_token()` exigeait alpha **ET** chiffre → "Bouchard" rejeté
- Lookup DB : `WHERE value = ANY(...)` → match exact seulement
- "Julien Bouchard" dans la DB ne matchait jamais "Bouchard" seul

### Après (fonctionne)
1. **`_NAME_RE`** capture tous les mots avec majuscule initiale ≥ 3 chars
2. **`fuzzy_lookup_sensitive()`** compare chaque token extrait contre toutes
   les valeurs DB avec `partial_ratio` — "Bouchard" → score élevé contre "Julien Bouchard"
3. **`fuzzy_lookup_fulltext()`** compare le texte complet avec `token_set_ratio` —
   "Madame Julien Bouchard est cliente" → score élevé contre "Julien Bouchard"

### Seuil
`FUZZY_THRESHOLD = 85` dans `config/settings.py`.
Baisser à 80 pour plus de rappel, monter à 90 pour moins de faux positifs.
