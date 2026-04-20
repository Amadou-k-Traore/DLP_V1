"""
normalizer.py — Normalisation universelle anti-contournement DLP.

Principe : réduire tout texte à son squelette alphabétique canonique,
puis comparer les squelettes avec du fuzzy matching.
Peu importe ce que la personne invente comme contournement,
deux textes désignant la même donnée produiront des squelettes proches.

Pipeline appliqué à chaque token :
  1. Leetspeak → lettres normales        ('Jul13n' → 'Julien')
  2. Unicode NFKD → ASCII               ('Julіen' cyrillique → 'Julien')
  3. Supprimer tout sauf les lettres    ('bou;char' → 'bouchar')
  4. Minuscules

Pour le texte complet, en plus :
  A. Détecter les lettres isolées espacées et les fusionner
     ('J u l i e n B o u c h a r' → 'Julien Bouchar')
  B. Calculer le squelette de chaque token
  C. Ajouter les inversions  ('rahcuoB' → squelette inversé = 'bouchar')
"""
from __future__ import annotations

import re
import unicodedata
from typing import List

# ── Table leetspeak 
_LEET_TABLE = str.maketrans({
    '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
    '7': 't', '@': 'a', '$': 's', '!': 'i', '+': 't',
    '8': 'b', '6': 'g', '9': 'g',
})

# ── Mots courants à ignorer 
COMMON_WORDS: set = {
    "bonjour", "bonsoir", "merci", "salut", "allo", "oui", "non",
    "donc", "alors", "mais", "avec", "pour", "dans", "comment", "voici",
    "voila", "bien", "tres", "trop", "quel", "quelle", "cette", "ceci",
    "cela", "chez", "sans", "sous", "vers", "hello", "okay", "please",
    "thank", "thanks", "sorry", "here", "there", "where", "what", "when",
    "have", "from", "with", "just", "about", "also", "after", "before",
    "entre", "depuis", "pendant", "apres", "avant", "encore", "peut",
    "faire", "avoir", "etre", "aller", "venir", "voir", "savoir",
    "madame", "monsieur", "mademoiselle", "notre", "leurs", "leur",
    "nous", "vous", "elles", "sont", "sera", "comme", "tout", "toute",
    "tous", "aussi", "plus", "moins", "meme", "autre", "autres",
    "celui", "celle", "ceux", "dont", "quoi", "votre", "aide",
    "rapport", "pret", "allez", "resto", "texte", "ecrit", "ecris",
}

# Regex : séquence de lettres isolées séparées par espaces 
_ISOLATED_RE = re.compile(r"\b([A-Za-zÀ-ÿ])(?: ([A-Za-zÀ-ÿ])){2,}\b")


def _join_isolated_letters(text: str) -> str:
    """
    Reconstitue les mots épelés lettre par lettre en respectant
    les transitions de casse comme séparateurs de mots.

    'J u l i e n B o u c h a r' → 'Julien Bouchar'
    'B O U C H A R'              → 'BOUCHAR'
    'j u l i e n'               → 'julien'
    """
    def _merge(m: re.Match) -> str:
        chars = m.group(0).replace(" ", "")
        # Ré-insérer espaces aux transitions minuscule→majuscule
        result = chars[0]
        for i in range(1, len(chars)):
            if chars[i].isupper() and chars[i-1].islower():
                result += " "
            result += chars[i]
        return result
    return _ISOLATED_RE.sub(_merge, text)


def _unicode_to_ascii(text: str) -> str:
    """Convertit homoglyphes Unicode et caractères accentués en ASCII."""
    nfkd = unicodedata.normalize("NFKD", text)
    return "".join(c for c in nfkd if not unicodedata.combining(c))


def skeleton(word: str) -> str:
    """
    Réduit UN MOT à son squelette alphabétique canonique.

    Exemples :
      'bou;emchar'     → 'bouemchar'
      'B*O*U*C*H*A*R'  → 'bouchar'
      'Jul13n'         → 'julien'
      'Julіen'         → 'julien'   (і cyrillique)
      'B.o.u.c.h.a.r'  → 'bouchar'
    """
    t = word.translate(_LEET_TABLE)          # 1. Leetspeak
    t = _unicode_to_ascii(t)                 # 2. Unicode → ASCII
    t = re.sub(r"[^A-Za-z]", "", t)         # 3. Lettres seulement
    return t.lower()                         # 4. Minuscules


def skeleton_tokens(text: str) -> List[str]:
    """
    Transforme un texte complet en liste de squelettes significatifs.

    1. Fusionner lettres isolées espacées
    2. Découper sur espaces (les séparateurs dans un mot → skeleton())
    3. Squelette de chaque token
    4. Filtrer : >= 4 chars, hors mots courants
    """
    t = _join_isolated_letters(text)
    words = t.split()
    result = []
    for w in words:
        sk = skeleton(w)
        if len(sk) >= 4 and sk not in COMMON_WORDS:
            result.append(sk)
    return result


def all_skeletons(text: str) -> List[str]:
    """
    Retourne tous les squelettes du texte + leurs versions inversées.
    L'inversion permet de détecter 'rahcuoB' → inversé = 'bouchar'.
    """
    normal   = skeleton_tokens(text)
    inversed = [s[::-1] for s in normal]
    seen, result = set(), []
    for s in normal + inversed:
        if s not in seen:
            seen.add(s)
            result.append(s)
    return result


def db_skeleton_tokens(db_value: str) -> List[str]:
    """
    Calcule les squelettes d'une valeur DB.
    Pas de filtre COMMON_WORDS car une valeur DB peut être un prénom court.
    Seuil minimal : 3 chars.
    """
    words = db_value.split()
    return [skeleton(w) for w in words if len(skeleton(w)) >= 3]



# LCS RECALL — détection de bruit injecté


def lcs_length(a: str, b: str) -> int:
    """
    Longueur de la plus longue sous-séquence commune (LCS).
    Ex: lcs('jupgbllien', 'juillien') = 7
    Les lettres de 'juillien' sont présentes dans 'jupgbllien'
    dans le bon ordre, malgré le bruit 'pgb' injecté.
    """
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
    return dp[m][n]


def lcs_recall(text_sk: str, db_sk: str) -> int:
    """
    Recall LCS : combien de lettres du mot DB (db_sk) sont présentes
    dans le squelette du texte (text_sk), dans le bon ordre.

    Score = lcs / len(db_sk) * 100

    Permet de détecter les injections de bruit aléatoire :
    Ex: 'jUP98Llien' → skeleton 'jupgbllien'
        lcs('jupgbllien', 'juillien') = 7/8 = 88% → DÉTECTÉ

    Différent du fuzzy ratio qui pénalise les caractères en trop.
    """
    lcs = lcs_length(text_sk, db_sk)
    return round(lcs / max(len(db_sk), 1) * 100)


def best_match_score(text_sk: str, db_sk: str) -> int:
    """
    Combine 3 métriques pour couvrir tous les types de contournement :

    1. sim() Levenshtein    : fautes de frappe  (juiliien → juillien)
    2. lcs_recall()         : bruit injecté     (jUP98Llien → juillien)
    3. lcs inverse          : variantes courtes (juiilen → juillien)
                              seulement si len(text) >= 75% len(db)
                              pour éviter les faux positifs sur mots courts

    On prend le max des 3 scores.
    """
    from rapidfuzz import fuzz
    s1 = fuzz.ratio(text_sk, db_sk)
    s2 = lcs_recall(text_sk, db_sk)
    # LCS inverse : uniquement si le mot saisi est assez long
    min_len = round(len(db_sk) * 0.75)
    s3 = lcs_recall(db_sk, text_sk) if len(text_sk) >= min_len else 0
    return max(s1, s2, s3)
