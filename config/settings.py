import os
import re
from typing import List


# PostgreSQL

PG_HOST = os.getenv("PG_HOST", "10.22.1.69")
PG_PORT = int(os.getenv("PG_PORT", "5432"))
PG_DB   = os.getenv("PG_DB",   "postgres")
PG_USER = os.getenv("PG_USER", "dta_user")

PG_PASS = os.getenv("PG_PASS")
if not PG_PASS:
    raise EnvironmentError(
        "La variable d'environnement PG_PASS est obligatoire.\n"
        "Windows : setx PG_PASS \"votre_mot_de_passe\"\n"
        "Linux   : export PG_PASS=\"votre_mot_de_passe\""
    )


# Fichiers de logs
# TOUS dans backend_output\logs\ 

BASE_LOG = r"C:\Users\Amadou\OneDrive\Bureau\REDD-TESTE\Backend\backend_output\logs"

CHAT_LOG_JSONL = os.getenv(
    "CHAT_LOG_JSONL",
    BASE_LOG + r"\chat_input.jsonl",
)
MEDIA_LOG_JSONL = os.getenv(
    "MEDIA_LOG_JSONL",
    BASE_LOG + r"\media_uploads.jsonl",
)
CUSTOM_ALERT_LOG = os.getenv(
    "CUSTOM_ALERT_LOG",
    BASE_LOG + r"\Custom_alert.log",
)
UI_DECISIONS_JSONL = os.getenv(
    "UI_DECISIONS_JSONL",
    BASE_LOG + r"\ollama_dta_decisions.jsonl",
)
DTA_EXEC_LOG = os.getenv(
    "DTA_EXEC_LOG",
    BASE_LOG + r"\dta_exec.log",
)


# Timings

REFRESH_INTERVAL_SEC = 60
POLL_SLEEP_SEC       = 0.25


# Politique de sanctions

HARD_BLOCK_MINUTES          = 5
QUARANTINE_TRIGGER_ATTEMPTS = 30
QUARANTINE_WINDOW_MIN       = 5
QUARANTINE_DURATION_MIN     = 5


# Limites de traitement

HASH_PREFIX_LEN         = 16
MAX_TEXT_LEN            = 200_000
MAX_CANDIDATES_PER_TEXT = 500
MAX_SEGMENTS_FOR_NER    = 100


# Queue asynchrone

QUEUE_MAX_SIZE    = 10_000
QUEUE_NUM_WORKERS = 4


# Seuil de similarité fuzzy

FUZZY_THRESHOLD = 85


# LLM Filtre — Ollama gemma3:4b

OLLAMA_BASE_URL    = os.getenv("OLLAMA_BASE_URL",    "http://localhost:11434")
LLM_FILTER_MODEL   = os.getenv("LLM_FILTER_MODEL",   "gemma3:4b")
LLM_FILTER_TIMEOUT = float(os.getenv("LLM_FILTER_TIMEOUT", "20.0"))
LLM_FILTER_ENABLED = os.getenv("LLM_FILTER_ENABLED", "true").lower() == "true"


# Regex de détection

EMAIL_RE    = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b")
LONG_NUM_RE = re.compile(r"\b\d{6,}\b")
PHONE_RE    = re.compile(r"\b(?:\+?\d[\d\-\s\(\)]{7,}\d)\b")
PASSPORT_RE = re.compile(r"\b[A-Z]{1,3}-[A-Z0-9]{4,}\b")
ID_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_-]{5,}\b")

POTENTIAL_NAS_RE = re.compile(r"\b\d{3}[- ]?\d{3}[- ]?\d{3}\b")
POTENTIAL_DOB_RE = re.compile(
    r"\b(19|20)\d{2}[-/](0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])\b"
)

INTENT_PATTERNS: List[re.Pattern] = [
    re.compile(r"\b(export|download|dump|exfiltrate|leak|extract|send|forward|share|upload)\b", re.I),
    re.compile(r"\b(show|give|list|retrieve)\s+(me\s+)?(all|the)\b", re.I),
    re.compile(r"\b(customer|client)\s+(database|list|records|accounts?)\b", re.I),
    re.compile(r"\b(bank|account)\s+(number|numbers|accounts?)\b", re.I),
    re.compile(r"\b(phone|email|passport|nas|ssn|iban|card|cards)\b", re.I),
]


# NER spaCy

ENABLE_NER   = True
SPACY_MODELS = ["fr_core_news_sm", "en_core_web_sm"]

COMMON_GPE = {
    "canada", "quebec", "québec", "montreal", "montréal", "toronto",
    "paris", "france", "usa", "united states", "senegal", "sénégal",
    "saguenay", "chicoutimi",
}
COMMON_ORG  = {"uqac", "openai", "google", "microsoft", "ollama"}
COMMON_MISC = {"bank", "client", "customer", "database"}
