"""
Simple Substitution Cipher + automatic cryptanalysis   (VTU BIS703, Module 1)

Encryption : every plaintext letter is replaced by a fixed letter from a 26-letter key.
Attack     : frequency analysis + hill climbing. It starts from a guess based on
             letter frequencies, then keeps swapping letters of the key whenever the
             decrypted text looks more like English (letter, bigram and trigram scores).
"""

import math
import random
import string
from collections import Counter

from ciphers import ENGLISH_FREQ

ALPHA = string.ascii_uppercase

_FREQ_ORDER = "ETAOINSRHLDCUMFPGWYBVKXJQZ"  # English letters, most to least common

_BIGRAMS = {
    "TH": 3.56, "HE": 3.07, "IN": 2.43, "ER": 2.05, "AN": 1.99, "RE": 1.85,
    "ON": 1.76, "AT": 1.49, "EN": 1.45, "ND": 1.35, "TI": 1.34, "ES": 1.34,
    "OR": 1.28, "TE": 1.20, "OF": 1.17, "ED": 1.17, "IS": 1.13, "IT": 1.12,
    "AL": 1.09, "AR": 1.07, "ST": 1.05, "TO": 1.04, "NT": 1.04, "NG": 0.95,
    "SE": 0.93, "HA": 0.93, "AS": 0.87, "OU": 0.87, "IO": 0.83, "LE": 0.83,
    "VE": 0.83, "CO": 0.79, "ME": 0.79, "DE": 0.76, "HI": 0.76, "RI": 0.73,
    "RO": 0.73, "IC": 0.70, "NE": 0.69, "EA": 0.69, "RA": 0.69, "CE": 0.65,
    "LI": 0.62, "CH": 0.60, "LL": 0.58, "BE": 0.58, "MA": 0.57, "SI": 0.55,
    "OM": 0.55, "UR": 0.54, "CA": 0.54, "EL": 0.53, "TA": 0.53, "LA": 0.52,
    "NS": 0.51, "DI": 0.51, "FO": 0.50, "HO": 0.50, "PE": 0.49, "EC": 0.49,
    "PR": 0.47, "NO": 0.47, "CT": 0.46, "US": 0.46, "AC": 0.45, "OT": 0.45,
    "IL": 0.44, "TR": 0.44, "LY": 0.43, "NC": 0.42, "ET": 0.41, "UT": 0.41,
    "SS": 0.40, "SO": 0.40, "RS": 0.39, "UN": 0.39, "LO": 0.38, "WA": 0.38,
    "GE": 0.37, "IE": 0.37, "WH": 0.36, "EE": 0.36, "WI": 0.35, "EM": 0.35,
    "AD": 0.35, "OL": 0.34, "RT": 0.34, "PO": 0.33, "WE": 0.33, "NA": 0.33,
    "UL": 0.32, "NI": 0.31, "TS": 0.31, "MO": 0.31, "OW": 0.30, "PA": 0.30,
    "IM": 0.30, "MI": 0.29, "AI": 0.29, "SH": 0.29, "IR": 0.28, "SU": 0.28,
    "ID": 0.27, "OS": 0.27, "IV": 0.27, "IA": 0.26, "AM": 0.26, "FI": 0.26,
    "CI": 0.25, "VI": 0.25, "PL": 0.25, "IG": 0.24, "TU": 0.24, "EV": 0.23,
    "LD": 0.23, "RY": 0.23, "MP": 0.22, "FE": 0.22, "BL": 0.22, "AB": 0.22,
    "GH": 0.21, "TY": 0.21, "OP": 0.21, "WO": 0.20, "SA": 0.20, "AY": 0.20,
    "EX": 0.20, "KE": 0.19, "FR": 0.19, "OO": 0.19, "AV": 0.18, "AG": 0.18,
    "IF": 0.18, "AP": 0.18, "GR": 0.17, "OD": 0.17, "BO": 0.17, "SP": 0.17,
    "RD": 0.16, "DO": 0.16, "UC": 0.16, "BU": 0.16, "EI": 0.16, "OV": 0.15,
    "BY": 0.15, "RM": 0.15, "EP": 0.15, "TT": 0.15, "OC": 0.15, "FA": 0.14,
    "EF": 0.14, "CU": 0.14, "RN": 0.14, "SC": 0.14, "GI": 0.14, "DA": 0.14,
    "YO": 0.13, "CR": 0.13, "CL": 0.13, "DU": 0.12, "GA": 0.12, "QU": 0.12,
    "UE": 0.12, "FF": 0.12, "BA": 0.12, "EY": 0.12, "LS": 0.11, "VA": 0.11,
    "UM": 0.11, "PP": 0.11, "UA": 0.11, "UP": 0.11, "LU": 0.10, "GO": 0.10,
    "HT": 0.10, "RU": 0.10, "UG": 0.10, "DS": 0.10, "LT": 0.10, "PI": 0.10,
    "RC": 0.09, "RR": 0.09, "EG": 0.09, "AU": 0.09, "CK": 0.09, "EW": 0.09,
    "MU": 0.09, "BR": 0.08, "BI": 0.08, "PT": 0.08, "AK": 0.08, "PU": 0.08,
    "UI": 0.08, "RG": 0.08, "IB": 0.08, "TL": 0.08, "NY": 0.08, "KI": 0.08,
    "RK": 0.07, "YS": 0.07, "OB": 0.07, "MM": 0.07, "FU": 0.07, "PH": 0.07,
    "OG": 0.07, "MS": 0.07, "YE": 0.07, "UD": 0.06, "MB": 0.06, "IP": 0.06,
    "UB": 0.06, "OI": 0.06, "RL": 0.06, "GU": 0.06, "DR": 0.06, "HR": 0.06,
    "CC": 0.06, "TW": 0.06, "FT": 0.06, "WN": 0.06, "NU": 0.05, "AF": 0.05,
    "HU": 0.05, "NN": 0.05, "EO": 0.05, "VO": 0.05, "RV": 0.05, "NF": 0.05,
    "XP": 0.05, "GN": 0.05, "SM": 0.05, "FL": 0.05, "IZ": 0.05, "OK": 0.05,
    "NL": 0.04, "MY": 0.04, "GL": 0.04, "AW": 0.04, "JU": 0.04, "OA": 0.04,
    "EQ": 0.04, "SY": 0.04, "SL": 0.04, "PS": 0.04, "JO": 0.04, "LF": 0.04,
    "NV": 0.04, "JE": 0.04, "NK": 0.04, "KN": 0.04, "GS": 0.04, "DY": 0.03,
    "HY": 0.03, "ZE": 0.03, "KS": 0.03, "XT": 0.03, "BS": 0.03, "IK": 0.03,
    "DD": 0.03, "CY": 0.03, "RP": 0.03, "SK": 0.03, "XI": 0.03, "OE": 0.03,
    "OY": 0.03, "WS": 0.03, "LV": 0.03, "DL": 0.03, "RF": 0.03, "EU": 0.03,
    "DG": 0.03, "WR": 0.03, "XA": 0.02, "YA": 0.02, "TM": 0.02, "VY": 0.02,
}

_TRIGRAMS = {
    "THE": 1.81, "AND": 0.73, "THA": 0.33, "ENT": 0.42, "ING": 0.72, "ION": 0.42,
    "TIO": 0.31, "FOR": 0.34, "NDE": 0.20, "HAS": 0.17, "NCE": 0.20, "TIS": 0.12,
    "OFT": 0.12, "STH": 0.10, "MEN": 0.14, "HER": 0.36, "NTH": 0.33, "INT": 0.32,
    "ERE": 0.31, "VER": 0.28, "ALL": 0.26, "HIS": 0.26, "ITH": 0.25, "THI": 0.25,
    "ATI": 0.24, "OUR": 0.23, "ERS": 0.22, "ARE": 0.22, "EST": 0.22, "ONS": 0.21,
    "TER": 0.21, "WAS": 0.21, "OUL": 0.20, "ULD": 0.18, "HAT": 0.20, "ONE": 0.18,
    "ONT": 0.18, "IVE": 0.17, "ECT": 0.17, "OTH": 0.16, "RES": 0.16, "ANT": 0.16,
    "EAR": 0.16, "COM": 0.15, "PRO": 0.15, "ALL": 0.26, "YOU": 0.15, "NOT": 0.15,
    "SIO": 0.14, "STA": 0.14, "ATE": 0.14, "BUT": 0.13, "EVE": 0.13, "ESS": 0.13,
}

_MONO_LOG = [math.log(ENGLISH_FREQ[c] / 100) for c in ALPHA]
_BI_FLOOR = math.log(0.01 / 100)
_BI = [[_BI_FLOOR] * 26 for _ in range(26)]
for _bg, _p in _BIGRAMS.items():
    _BI[ord(_bg[0]) - 65][ord(_bg[1]) - 65] = math.log(_p / 100)
_TRI_FLOOR = math.log(0.005 / 100)
_TRI = {tuple(ord(c) - 65 for c in _tg): math.log(_p / 100) for _tg, _p in _TRIGRAMS.items()}


# ---------------------------------------------------------------- keys
def generate_key(rng=None):
    """Random 26-letter substitution key (a shuffled alphabet)."""
    rng = rng or random.SystemRandom()
    letters = list(ALPHA)
    rng.shuffle(letters)
    return "".join(letters)


def keyword_key(keyword):
    """Key built from a keyword (duplicates removed) followed by the unused letters."""
    seen, out = set(), []
    for ch in "".join(c for c in keyword.upper() if c.isalpha()) + ALPHA:
        if ch not in seen:
            seen.add(ch)
            out.append(ch)
    return "".join(out)


def validate_key(key):
    key = "".join(key.upper().split())
    if len(key) != 26 or sorted(key) != list(ALPHA):
        raise ValueError("Key must contain each of the 26 letters A-Z exactly once.")
    return key


# ---------------------------------------------------------------- cipher
def _translate(text, mapping):
    out = []
    for ch in text:
        if ch.isupper() and ch in mapping:
            out.append(mapping[ch])
        elif ch.islower() and ch.upper() in mapping:
            out.append(mapping[ch.upper()].lower())
        else:
            out.append(ch)
    return "".join(out)


def substitution_encrypt(text, key):
    key = validate_key(key)
    return _translate(text, dict(zip(ALPHA, key)))


def substitution_decrypt(text, key):
    key = validate_key(key)
    return _translate(text, dict(zip(key, ALPHA)))


# ---------------------------------------------------------------- attack
def substitution_attack(ciphertext, restarts=12, seed=None):
    """
    Break a simple substitution cipher without the key.

    Returns (key, plaintext_guess, score). `key` is in the same format as the
    encryption key. Works best with 200+ letters of English text; very short
    texts do not contain enough statistics, so the result may be only partly right.
    """
    rng = random.Random(seed)
    letters = [ord(c) - 65 for c in ciphertext.upper() if c.isalpha()]
    if len(letters) < 30:
        raise ValueError("Need at least about 30 letters of ciphertext for frequency analysis.")

    mono = Counter(letters)
    bi = Counter(zip(letters, letters[1:]))
    tri = Counter(zip(letters, letters[1:], letters[2:]))

    def score(dec):
        s = 0.0
        for c, n in mono.items():
            s += n * _MONO_LOG[dec[c]]
        for (a, b), n in bi.items():
            s += n * _BI[dec[a]][dec[b]]
        for (a, b, c), n in tri.items():
            s += n * _TRI.get((dec[a], dec[b], dec[c]), _TRI_FLOOR)
        return s

    # Step 1: frequency analysis - match cipher letters to English letters by rank.
    ranked = [c for c, _ in mono.most_common()]
    order = ranked + [c for c in range(26) if c not in mono]
    start = [0] * 26
    for rank, c in enumerate(order):
        start[c] = ord(_FREQ_ORDER[rank]) - 65

    # Step 2: hill climbing - swap pairs until the text looks as English as possible.
    best_dec, best_score = None, float("-inf")
    for r in range(restarts):
        if best_dec is None:
            dec = start[:]
        else:
            dec = best_dec[:] if r % 3 else start[:]
            for _ in range(rng.randint(2, 6)):
                i, j = rng.sample(range(26), 2)
                dec[i], dec[j] = dec[j], dec[i]
        cur = score(dec)
        improved = True
        while improved:
            improved = False
            for i in range(25):
                for j in range(i + 1, 26):
                    dec[i], dec[j] = dec[j], dec[i]
                    s = score(dec)
                    if s > cur + 1e-9:
                        cur, improved = s, True
                    else:
                        dec[i], dec[j] = dec[j], dec[i]
        if cur > best_score:
            best_score, best_dec = cur, dec[:]

    enc_key = [""] * 26
    for c in range(26):
        enc_key[best_dec[c]] = chr(c + 65)
    key = "".join(enc_key)
    return key, substitution_decrypt(ciphertext, key), best_score
