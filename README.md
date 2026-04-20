
# Documentation Technique — Système DLP

---

## 1. Vue d'ensemble du projet

Le système **DLP** est un prototype de recherche académique implémentant un système **DLP (Data Loss Prevention)**  pour détecter et bloquer les fuites de données personnelles sensibles dans un chatbot basé sur un LLM local (Ollama).

### 1.1 Objectif

Empêcher qu'un utilisateur malveillant ou négligent puisse envoyer des données personnelles (PII) à un chatbot IA, en interceptant et analysant chaque message **avant** qu'il ne soit traité par le modèle de langage.

### 1.2 Contributions scientifiques (C1–C4)

| Contribution | Description |
|---|---|
| **C1** | Classification binaire LLM locale — détecte si un prompt contient des données sensibles |
| **C2** | Extraction contextuelle LLM — identifie les entités précises (noms, NAS, dates, etc.) |
| **C3** | Comparaison fuzzy ciblée sur entités extraites (au lieu du texte complet) |
| **C4** | Analyse Jaccard par trigrammes sur entités extraites |

---

## 2. Architecture du système

### 2.1 Composants

```
DLP-REED/
├── Backend/        — API FastAPI (Python) — reçoit les messages du frontend
├── DLP/            — DLP-REED — pipeline de détection
└── Frontend/       — Interface web HTML/CSS/JS
```

### 2.2 Flux de données complet

```
Utilisateur → Frontend → Backend → [DLP_MAX_WAIT=25s] → Ollama chat
                                        ↓
                                       DTA lit le message
                                        ↓
                              C1 — gemma3:4b classifie
                                        ↓
                         sensitive=false (95%) → STOP — aucune DB
                                        ↓
                         sensitive=true  (5%) → pipeline continue
                                        ↓
                              C2 — entités extraites
                                        ↓
                         C3 — Fuzzy sur entités → BLOQUÉ si match
                                        ↓
                         C4 — Jaccard sur entités → BLOQUÉ si match
                                        ↓
                         N2 — Squelette anti-obfuscation → BLOQUÉ si match
                                        ↓
                         N3 — Intent + NER → SOFT BLOQUÉ si match
                                        ↓
                         Backend poll PostgreSQL → voit blocage → 403
                         Ollama chat ne reçoit JAMAIS le message
```

### 2.3 Infrastructure

| Composant | Technologie | Port |
|---|---|---|
| Backend API | FastAPI + uvicorn | 8000 |
| Base de données | PostgreSQL | 5432 (10.22.1.69) |
| LLM filtre + chat | Ollama | 11434 |
| Modèle filtre | gemma3:4b (4.3 GB) | — |
| Modèle chat | gemma3:4b (4.3 GB) | — |

---

## 3. Pipeline de détection DLP (C1–C4)

### 3.1 C1 — Classification LLM (llm_filter.py)

Le premier filtre appelle `gemma3:4b` via Ollama pour classifier binairement le prompt :

```python
# Retourne {"sensitive": false} ou {"sensitive": true, "entities": [...]}
result = llm_classify_and_extract(text)
```

**Si sensitive=false (≈95% des prompts)** : return immédiat, zéro consultation DB, zéro fuzzy.

**Si sensitive=true (≈5%)** : pipeline continue avec les entités extraites.

**Prompt système envoyé au LLM :**
```
Tu es un classificateur de securite DLP.
Données sensibles à détecter :
- Noms de personnes
- Numéros (NAS, téléphone, passeport, compte)
- Adresses email ou physiques
- Dates de naissance
- Données obfusquées (leetspeak, séparateurs)
Réponds UNIQUEMENT avec JSON : {"sensitive": true/false, "entities": [...]}
```

### 3.2 C2 — Extraction d'entités (llm_filter.py)

Quand `sensitive=true`, le LLM retourne les valeurs brutes extraites :
```json
{"sensitive": true, "entities": ["Julien Bouchard", "527 831 649"]}
```

Ces entités sont passées aux niveaux suivants au lieu du texte complet — réduction drastique des comparaisons DB.

### 3.3 C3 — Fuzzy sur entités (text.py → free_text_lookup)

Compare uniquement les entités extraites (2-5 mots) contre les 690 entrées DB :

```python
# Seuils
FREE_TEXT_BLOCK_THRESHOLD = 92   # score ≥ 92% → hard_block
FREE_TEXT_WARN_THRESHOLD  = 86   # score ≥ 86% → soft_block

# 4 métriques rapidfuzz combinées
scores = {
    "ratio":            fuzz.ratio(candidate, db_val),
    "partial_ratio":    fuzz.partial_ratio(candidate, db_val),
    "token_sort_ratio": fuzz.token_sort_ratio(candidate, db_val),
    "token_set_ratio":  fuzz.token_set_ratio(candidate, db_val),
}
```

### 3.4 C4 — Jaccard par trigrammes sur entités (ngram.py)

Détecte les variantes et fautes d'orthographe légères :

```python
# Seuils Jaccard
JACCARD_WARN_THRESHOLD  = 0.40
JACCARD_BLOCK_THRESHOLD = 0.55

# Exemple : "bouchar" vs "Bouchard"
# trigrammes bouchar : {bou, ouc, uch, cha, har}
# trigrammes Bouchard : {bou, ouc, uch, cha, har, arc, rch}
# Jaccard = 5/7 = 0.71 ≥ 0.55 → BLOQUÉ
```

### 3.5 N2 — Squelette anti-obfuscation (text.py → skeleton_lookup)

Détecte les tentatives de contournement : `b.o.u.c.h.a.r`, `Jul13n`, `B O U C H A R D` :

```python
# Filtre : ignore les valeurs DB < 7 caractères (évite faux positifs)
if len(db_val.strip()) < 7:
    continue

# Seuil
SKELETON_THRESHOLD = 78   # score ≥ 78% → hard_block
```

### 3.6 N3 — Intent + NER + Patterns (text.py → detect_text)

Fallback sémantique si les niveaux précédents ne détectent rien :

```python
# Intent patterns
if score >= 2:
    apply_soft_block(...)   # "download all customer database"

# NER spaCy
if len(entities) >= 2 and score >= 1:
    apply_soft_block(...)

# Patterns regex
if POTENTIAL_NAS_RE.search(text) or POTENTIAL_DOB_RE.search(text):
    apply_soft_block(...)
```

---

## 4. Politique de sanctions

| Niveau | Déclencheur | Durée |
|---|---|---|
| **soft_block** | Score 86-91% ou intent | Avertissement |
| **hard_block** | Score ≥ 92% ou skeleton | 60 minutes |
| **quarantine** | 3 tentatives en 10 min | 30 minutes |

---

## 5. Base de données sensibles

**690 entrées PII réelles** organisées en labels :

| Table | Labels | Exemples |
|---|---|---|
| bank.clients | nom, prenom, nas, email, telephone, date_naissance, adresse_ligne1, code_postal, passport_num | Bouchard, Tremblay, 527831649 |
| bank.authentification | username, password_hash, last_login_ip, last_session_id, salt, mfa_secret_ref | amadou.diallo, sess_abc123 |
| bank.cartes | last4, pin_hash, token_pan | 4321, tok_abc123 |
| bank.comptes_bancaires | numero_compte, account_key | 800987654, 002-10003 |
| bank.transactions | reference, marchand, ip_source, device_id | — |
| bank.logs_systeme | ip, device_id, correlation_id | 10.22.1.69 |
| bank.documents_client | numero_doc, file_path | CA-P1000003, DL-200001 |

---

## 6. Configuration technique

### 6.1 DLP/config/settings.py

```python
# LLM Filtre
OLLAMA_BASE_URL    = "http://localhost:11434"
LLM_FILTER_MODEL   = "gemma3:4b"
LLM_FILTER_TIMEOUT = 15.0   # secondes
LLM_FILTER_ENABLED = True

# Seuils de détection
FREE_TEXT_BLOCK_THRESHOLD = 92
FREE_TEXT_WARN_THRESHOLD  = 86
SKELETON_THRESHOLD        = 78
JACCARD_BLOCK_THRESHOLD   = 0.55

# Politique
HARD_BLOCK_MINUTES          = 60
QUARANTINE_TRIGGER_ATTEMPTS = 3
QUARANTINE_DURATION_MIN     = 30

# Chemins logs
BASE_LOG = r"C:\Users\Amadou\OneDrive\Bureau\REDD-TESTE\Backend\backend_output\logs"
```

### 6.2 Backend/app/config.py

```python
ollama_base_url = "http://127.0.0.1:11434"
ollama_model    = "gemma3:4b"
log_dir         = r"C:\Users\Amadou\OneDrive\Bureau\REDD-TESTE\Backend\backend_output\logs"
DLP_MAX_WAIT    = 25.0   # secondes — temps d'attente décision DLA
DLP_POLL_INTERVAL = 0.25  # secondes — fréquence de poll PostgreSQL
```

---

## 7. Modèles Ollama utilisés

| Modèle | Taille | Rôle | Raison du choix |
|---|---|---|---|
| **gemma3:4b** | 4.3 GB | Filtre DLP + Chat | Modèle léger, bon équilibre performance/qualité, supporte JSON structuré |
| llama3.1 | 4.9 GB | (remplacé) | Trop lourd, contention avec le filtre |
| qwen3:1.7b | 1.9 GB | (abandonné) | Mode "thinking" → réponse vide, non adapté |
| gemma4:e2b | 4.4 GB | (abandonné) | LM Studio trop lent sur CPU (13-47s) |

---

## 8. Procédure de démarrage

```powershell
# 1. Charger le modèle Ollama
ollama run gemma3:4b --keepalive 120m

# 2. Démarrer le Backend
cd C:\Users\Amadou\OneDrive\Bureau\REDD-TESTE\Backend
.venv\Scripts\activate
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# 3. Démarrer le DTA
cd C:\Users\Amadou\OneDrive\Bureau\REDD-TESTE\DLP
$env:PG_PASS = "admin@2026"
python .\main.py

# 4. Surveiller les logs
Get-Content "...\backend_output\logs\dta_exec.log" -Tail 30 -Wait
```

---

## 9. Exemples de logs de détection

### Détection réussie — C1+C2+C3

```
detect_text: user=bob hash=c11c82737aca5bfe
llm_filter: model=gemma3:4b elapsed=8.735s
llm_filter: sensitive=True entities=['Julien Bouchard']
llm_filter: OUI sensible — entites=['Julien Bouchard']
free_text_lookup: mode ENTITES LLM (1 entites)
FREE_TEXT DETECTION user=bob score=100.0% label=bank.clients.nom
```

### Détection réussie — données multiples

```
llm_filter: sensitive=True
entities=['1987-04-12', '245 rue Saint-Jean', 'Québec']
FREE_TEXT DETECTION score=100.0% label=bank.clients.adresse_ligne1
candidate='245 rue Saint-Jean'
```

### Prompt innocent — élimination précoce C1

```
llm_filter: NON sensible — prompt autorise sans DB (user=amadou)
→ 0 comparaison DB, 0 fuzzy, 0 Jaccard
```

---

## 10. Utilisateurs de démonstration

| Username | Mot de passe | Rôle |
|---|---|---|
| amadou | Amadou@2026! | user |
| alice | Alice@2026! | user |
| bob | Bob@2026! | user |

---

## 11. Problèmes rencontrés et solutions

| Problème | Cause | Solution |
|---|---|---|
| Timeout LLM filtre | Contention Ollama — deux modèles différents | Un seul modèle gemma3:4b pour filtre ET chat |
| Faux positifs "parfais" | Squelette trop agressif sur mots courts | Filtre min 7 caractères dans skeleton_lookup |
| qwen3:1.7b raw='' | Mode "thinking" consomme tous les tokens | Abandonné, remplacé par gemma3:4b |
| LM Studio timeout 13s | CPU sans GPU — inférence lente | Retour à Ollama plus optimisé |
| PostgreSQL timeout | Machine distante éteinte ou réseau coupé | Vérifier connectivité 10.22.1.69:5432 |
| Message passé avant blocage | DLP_MAX_WAIT=8s insuffisant | Augmenté à 25s |

---

## 12. Structure des fichiers

```
DLP/
├── main.py                    — Point d'entrée DTA, gestion des threads
├── config/
│   └── settings.py            — Configuration globale (DB, LLM, seuils, chemins)
├── detection/
│   ├── llm_filter.py          — C1+C2 : filtre LLM gemma3:4b
│   ├── text.py                — Pipeline principal C3+C4+N2+N3
│   ├── ngram.py               — C4 : Jaccard trigrammes
│   ├── normalizer.py          — Squelettes et normalisation
│   ├── ner.py                 — NER spaCy (fr+en)
│   └── media.py               — Détection images/audio
├── db/
│   └── store.py               — Accès PostgreSQL
├── ioevents/
│   ├── events.py              — Lecture JSONL en temps réel (tail)
│   └── cache.py               — Cache des références média
├── policy/
│   └── actions.py             — apply_hard_block, apply_soft_block, apply_quarantine
└── utils/
    └── helpers.py             — exec_log, short_hash_text, ensure_file_exists

Backend/
├── app/
│   ├── main.py                — Routes FastAPI, poll DLP, envoi Ollama
│   ├── config.py              — Settings Backend (modèle, chemins, JWT)
│   ├── logger.py              — Écriture JSONL (chat_input, media, assistant)
│   ├── ollama_client.py       — Client HTTP Ollama async
│   ├── policy_service.py      — Lecture politique DLP depuis PostgreSQL
│   └── auth.py                — JWT authentification

Frontend/
└── index.html                 — Interface chat (HTML/CSS/JS vanilla)
```

---

## 13. Infrastructure Détaillée

### 13.1 Vue physique du réseau

```
┌─────────────────────────────────────────────────────────────┐
│                    RÉSEAU LOCAL (Wi-Fi)                      │
│                                                             │
│  ┌──────────────────────────────────────┐                  │
│  │   PC Amadou (Machine principale)      │                  │
│  │   IP : 10.22.1.59                    │                  │
│  │                                      │                  │
│  │   ┌─────────────┐ ┌──────────────┐  │                  │
│  │   │   Ollama    │ │   Backend    │  │                  │
│  │   │  port 11434 │ │  port 8000   │  │                  │
│  │   │  gemma3:4b  │ │  FastAPI     │  │                  │
│  │   └─────────────┘ └──────────────┘  │                  │
│  │                                      │                  │
│  │   ┌─────────────┐ ┌──────────────┐  │                  │
│  │   │     DTA     │ │  Frontend    │  │                  │
│  │   │  Pipeline   │ │  index.html  │  │                  │
│  │   │  C1-C4      │ │  navigateur  │  │                  │
│  │   └─────────────┘ └──────────────┘  │                  │
│  └──────────────────────────────────────┘                  │
│                          │                                  │
│                          │ TCP/IP port 5432                 │
│                          ▼                                  │
│  ┌──────────────────────────────────────┐                  │
│  │   Serveur PostgreSQL                  │                  │
│  │   IP : 10.22.1.69                    │                  │
│  │   Port : 5432                        │                  │
│  │   DB : postgres                      │                  │
│  │   User : dta_user                    │                  │
│  └──────────────────────────────────────┘                  │
└─────────────────────────────────────────────────────────────┘
```

### 13.2 Composants sur la machine principale (10.22.1.59)

| Composant | Technologie | Port | Rôle |
|---|---|---|---|
| Ollama | llama.cpp | 11434 | Moteur d'inférence LLM local |
| Backend | FastAPI + uvicorn | 8000 | API REST — reçoit les messages du frontend |
| DTA | Python threads | — | Analyse les messages en temps réel |
| Frontend | HTML/CSS/JS | — | Interface chat dans le navigateur |

### 13.3 Serveur PostgreSQL (10.22.1.69)

| Paramètre | Valeur |
|---|---|
| Host | 10.22.1.69 |
| Port | 5432 |
| Base de données | postgres |
| Utilisateur | dta_user |
| Mot de passe | admin@2026 |

**Tables utilisées :**

```sql
-- Table des données sensibles de référence
public.sensitive_text
  id        SERIAL PRIMARY KEY
  value     TEXT    -- valeur sensible (ex: "Bouchard")
  label     TEXT    -- étiquette (ex: "bank.clients.nom")

-- Table des politiques utilisateur
public.user_policy
  username          TEXT PRIMARY KEY
  action            TEXT    -- allow / soft_block / hard_block / quarantine
  policy_level      INT
  blocked_until     TIMESTAMP
  quarantine_until  TIMESTAMP
  strike_count      INT
  first_strike_at   TIMESTAMP
  reason            TEXT
  updated_at        TIMESTAMP

-- Table des médias sensibles
public.sensitive_media
  id        SERIAL PRIMARY KEY
  hash      TEXT    -- SHA256 du fichier
  label     TEXT    -- type de média sensible
```

---

## 14. Connectivité entre les composants

### 14.1 Flux de communication complet

```
Frontend (navigateur)
    │
    │ HTTP POST /api/login      → JWT token
    │ HTTP POST /api/chat       → message utilisateur
    │ HTTP GET  /api/policy     → statut DLP (poll toutes les 500ms)
    │
    ▼
Backend FastAPI (127.0.0.1:8000)
    │
    ├── Écrit dans ──────────────────────────────────────────────►
    │   backend_output\logs\chat_input.jsonl
    │                                                            │
    │                                              DTA lit le fichier JSONL
    │                                                            │
    │                                              DTA appelle Ollama
    │                                              POST /api/chat
    │                                              → gemma3:4b analyse
    │                                                            │
    ├── Poll PostgreSQL ◄─────────────── DTA écrit la décision ─┘
    │   SELECT * FROM user_policy
    │   toutes les 250ms (max 25s)
    │
    ├── Si bloqué → HTTP 403 → Frontend affiche blocage
    │
    └── Si non bloqué → POST Ollama /api/chat
                        → gemma3:4b génère réponse
                        → HTTP 200 → Frontend affiche réponse
```

### 14.2 Communication Backend → DTA

Le Backend et le DTA ne communiquent **pas directement** — ils utilisent deux mécanismes intermédiaires :

**Mécanisme 1 — Fichier JSONL (Backend → DTA)**

```
Backend écrit :
backend_output\logs\chat_input.jsonl

Exemple d'entrée :
{
  "event_type": "text",
  "username": "bob",
  "session_id": "sess_abc123",
  "request_id": "uuid-...",
  "text": "Madame Julien Bouchard",
  "timestamp": "2026-04-17T06:02:00Z"
}

DTA lit ce fichier en continu (tail) avec un marqueur .pos
pour reprendre exactement là où il s'est arrêté.
```

**Mécanisme 2 — PostgreSQL (DTA → Backend)**

```
DTA écrit la décision :
UPDATE public.user_policy
SET action='hard_block', reason='donnée sensible détectée'
WHERE username='bob'

Backend poll toutes les 250ms :
SELECT * FROM user_policy WHERE username='bob'
→ Voit le blocage → retourne 403 au frontend
```

### 14.3 Communication DLP→ Ollama

```python
# DTA appelle Ollama pour le filtre LLM (C1+C2)
POST http://localhost:11434/api/chat
{
  "model": "gemma3:4b",
  "messages": [
    {"role": "system", "content": "Tu es un classificateur DLP..."},
    {"role": "user",   "content": "Madame Julien Bouchard"}
  ],
  "stream": false,
  "options": {"temperature": 0.0, "num_predict": 128}
}

# Ollama répond
{
  "message": {
    "content": '{"sensitive": true, "entities": ["Julien Bouchard"]}'
  }
}
```

### 14.4 Communication Backend → Ollama (chat)

```python
# Backend appelle Ollama pour générer la réponse chat
POST http://127.0.0.1:11434/api/chat
{
  "model": "gemma3:4b",
  "messages": [
    {"role": "system",    "content": "You are a helpful assistant."},
    {"role": "user",      "content": "Bonjour comment allez-vous ?"}
  ],
  "stream": false
}
```

### 14.5 Timing et synchronisation

```
t=0ms    Utilisateur envoie le message
t=5ms    Backend reçoit et logue dans chat_input.jsonl
t=10ms   DTA lit le message (tail JSONL, poll 250ms)
t=10ms   DTA appelle Ollama → gemma3:4b classifie
t=8735ms gemma3:4b répond → sensitive=True, entities=['Julien Bouchard']
t=8740ms DTA appelle fuzzy → score 100% → BLOQUÉ
t=8745ms DTA écrit hard_block dans PostgreSQL
t=9000ms Backend poll PostgreSQL → voit blocage → retourne 403
t=9005ms Frontend affiche "🔒 Envoi bloqué"

→ Ollama chat ne reçoit JAMAIS le message sensible ✓
→ Total : ~9 secondes du message au blocage
```

---

## 15. Sécurité de la connexion PostgreSQL

```python
# Connexion sécurisée avec timeout
psycopg.connect(
    'host=10.22.1.69 port=5432 dbname=postgres user=dta_user password=admin@2026',
    connect_timeout=8
)
```

**Le mot de passe est passé via variable d'environnement** — jamais en dur dans le code de production :

```powershell
# Windows — définir avant de lancer le DTA
$env:PG_PASS = "admin@2026"
python .\main.py
```

**Vérification de connectivité :**

```powershell
# Tester la connexion réseau
Test-NetConnection -ComputerName 10.22.1.69 -Port 5432

# Tester la connexion PostgreSQL
python -c "
import psycopg
conn = psycopg.connect('host=10.22.1.69 port=5432 dbname=postgres user=dta_user password=admin@2026')
print('Connexion OK')
conn.close()
"
```

---

## 16. Logs et monitoring

### 16.1 Fichiers de logs

Tous les logs sont dans `Backend\backend_output\logs\` :

| Fichier | Contenu |
|---|---|
| `chat_input.jsonl` | Tous les messages envoyés par les utilisateurs |
| `media_uploads.jsonl` | Uploads d'images et fichiers audio |
| `assistant_output.jsonl` | Réponses générées par le LLM |
| `dta_exec.log` | Logs d'exécution du DLA en temps réel |
| `Custom_alert.log` | Alertes de sécurité Wazuh |
| `ollama_dta_decisions.jsonl` | Décisions DLP au format JSON |

### 16.2 Surveiller les logs en temps réel

```powershell
# Logs DTA en temps réel
Get-Content "C:\Users\Amadou\OneDrive\Bureau\REDD-TESTE\Backend\backend_output\logs\dta_exec.log" -Tail 30 -Wait
```   
## Remplacer ce chemim par celle de votre machine.

### 16.3 Débloquer un utilisateur manuellement

```sql
UPDATE public.user_policy
SET action='allow', policy_level=0, blocked_until=NULL,
    quarantine_until=NULL, strike_count=0, first_strike_at=NULL,
    reason=NULL, updated_at=NOW()
WHERE username = 'bob';
```

