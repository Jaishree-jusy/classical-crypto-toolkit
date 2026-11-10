"""
Classical Cipher Toolkit - core logic
Ciphers: Caesar, Vigenere, Playfair, Hill (2x2), Rail Fence
Attacks: Caesar brute force, Caesar frequency analysis, letter frequency count
"""

import string
from collections import Counter

ALPHA = string.ascii_uppercase


# ---------------------------------------------------------------- helpers
def _shift_char(ch, shift):
    """Shift one letter, keeping case. Non-letters are returned unchanged."""
    if ch.isupper():
        return chr((ord(ch) - 65 + shift) % 26 + 65)
    if ch.islower():
        return chr((ord(ch) - 97 + shift) % 26 + 97)
    return ch


def _letters_only(text):
    return "".join(c for c in text.upper() if c.isalpha())


def _mod_inverse(a, m):
    a %= m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("No modular inverse exists")


# ---------------------------------------------------------------- Caesar
def caesar_encrypt(text, shift):
    return "".join(_shift_char(c, shift) for c in text)


def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)


# ---------------------------------------------------------------- Vigenere
def vigenere_encrypt(text, key):
    key = _letters_only(key)
    if not key:
        raise ValueError("Key must contain at least one letter")
    out, i = [], 0
    for c in text:
        if c.isalpha():
            out.append(_shift_char(c, ord(key[i % len(key)]) - 65))
            i += 1
        else:
            out.append(c)
    return "".join(out)


def vigenere_decrypt(text, key):
    key = _letters_only(key)
    if not key:
        raise ValueError("Key must contain at least one letter")
    out, i = [], 0
    for c in text:
        if c.isalpha():
            out.append(_shift_char(c, -(ord(key[i % len(key)]) - 65)))
            i += 1
        else:
            out.append(c)
    return "".join(out)


# ---------------------------------------------------------------- Playfair
def _playfair_matrix(key):
    key = _letters_only(key).replace("J", "I")
    seen, matrix = set(), []
    for ch in key + ALPHA.replace("J", ""):
        if ch not in seen:
            seen.add(ch)
            matrix.append(ch)
    return [matrix[i:i + 5] for i in range(0, 25, 5)]


def _find(matrix, ch):
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == ch:
                return r, c


def _playfair_prepare(text):
    text = _letters_only(text).replace("J", "I")
    digraphs, i = [], 0
    while i < len(text):
        a = text[i]
        b = text[i + 1] if i + 1 < len(text) else "X"
        if a == b:
            digraphs.append(a + "X")
            i += 1
        else:
            digraphs.append(a + b)
            i += 2
    if digraphs and len(digraphs[-1]) == 1:
        digraphs[-1] += "X"
    return digraphs


def playfair_matrix_text(key):
    """Return the 5x5 matrix as a printable string (useful for the GUI/report)."""
    return "\n".join(" ".join(row) for row in _playfair_matrix(key))


def playfair_encrypt(text, key):
    m = _playfair_matrix(key)
    out = []
    for pair in _playfair_prepare(text):
        r1, c1 = _find(m, pair[0])
        r2, c2 = _find(m, pair[1])
        if r1 == r2:
            out.append(m[r1][(c1 + 1) % 5] + m[r2][(c2 + 1) % 5])
        elif c1 == c2:
            out.append(m[(r1 + 1) % 5][c1] + m[(r2 + 1) % 5][c2])
        else:
            out.append(m[r1][c2] + m[r2][c1])
    return "".join(out)


def playfair_decrypt(text, key):
    m = _playfair_matrix(key)
    text = _letters_only(text)
    if len(text) % 2:
        raise ValueError("Playfair ciphertext must have an even number of letters")
    out = []
    for i in range(0, len(text), 2):
        r1, c1 = _find(m, text[i])
        r2, c2 = _find(m, text[i + 1])
        if r1 == r2:
            out.append(m[r1][(c1 - 1) % 5] + m[r2][(c2 - 1) % 5])
        elif c1 == c2:
            out.append(m[(r1 - 1) % 5][c1] + m[(r2 - 1) % 5][c2])
        else:
            out.append(m[r1][c2] + m[r2][c1])
    return "".join(out)  # may contain filler X and I for J (known Playfair limitation)


# ---------------------------------------------------------------- Hill (2x2)
def _hill_key_matrix(key):
    """Key: 4 letters (e.g. 'GYBN') or 4 numbers separated by spaces/commas."""
    parts = key.replace(",", " ").split()
    if len(parts) == 4 and all(p.lstrip("-").isdigit() for p in parts):
        nums = [int(p) % 26 for p in parts]
    else:
        letters = _letters_only(key)
        if len(letters) != 4:
            raise ValueError("Hill key must be 4 letters (e.g. GYBN) or 4 numbers")
        nums = [ord(c) - 65 for c in letters]
    a, b, c, d = nums
    det = (a * d - b * c) % 26
    try:
        inv_det = _mod_inverse(det, 26)
    except ValueError:
        raise ValueError("Invalid Hill key: determinant has no inverse mod 26. Try another key.")
    return [[a, b], [c, d]], det, inv_det


def hill_encrypt(text, key):
    k, _, _ = _hill_key_matrix(key)
    text = _letters_only(text)
    if len(text) % 2:
        text += "X"
    out = []
    for i in range(0, len(text), 2):
        x, y = ord(text[i]) - 65, ord(text[i + 1]) - 65
        out.append(chr((k[0][0] * x + k[0][1] * y) % 26 + 65))
        out.append(chr((k[1][0] * x + k[1][1] * y) % 26 + 65))
    return "".join(out)


def hill_decrypt(text, key):
    k, _, inv_det = _hill_key_matrix(key)
    inv = [
        [(k[1][1] * inv_det) % 26, (-k[0][1] * inv_det) % 26],
        [(-k[1][0] * inv_det) % 26, (k[0][0] * inv_det) % 26],
    ]
    text = _letters_only(text)
    if len(text) % 2:
        raise ValueError("Hill ciphertext must have an even number of letters")
    out = []
    for i in range(0, len(text), 2):
        x, y = ord(text[i]) - 65, ord(text[i + 1]) - 65
        out.append(chr((inv[0][0] * x + inv[0][1] * y) % 26 + 65))
        out.append(chr((inv[1][0] * x + inv[1][1] * y) % 26 + 65))
    return "".join(out)


# ---------------------------------------------------------------- Rail Fence
def _rail_pattern(length, rails):
    pattern, rail, step = [], 0, 1
    for _ in range(length):
        pattern.append(rail)
        if rails > 1:
            if rail == 0:
                step = 1
            elif rail == rails - 1:
                step = -1
            rail += step
    return pattern


def railfence_encrypt(text, rails):
    if rails < 2:
        raise ValueError("Rails must be at least 2")
    pattern = _rail_pattern(len(text), rails)
    return "".join(text[i] for r in range(rails) for i in range(len(text)) if pattern[i] == r)


def railfence_decrypt(text, rails):
    if rails < 2:
        raise ValueError("Rails must be at least 2")
    pattern = _rail_pattern(len(text), rails)
    order = [i for r in range(rails) for i in range(len(text)) if pattern[i] == r]
    out = [""] * len(text)
    for pos, ch in zip(order, text):
        out[pos] = ch
    return "".join(out)


def railfence_grid(text, rails):
    """Zig-zag grid as a string, for the GUI/report."""
    pattern = _rail_pattern(len(text), rails)
    rows = []
    for r in range(rails):
        rows.append(" ".join(text[i] if pattern[i] == r else "." for i in range(len(text))))
    return "\n".join(rows)


# ---------------------------------------------------------------- Attacks
ENGLISH_FREQ = {
    "A": 8.17, "B": 1.49, "C": 2.78, "D": 4.25, "E": 12.70, "F": 2.23, "G": 2.02,
    "H": 6.09, "I": 6.97, "J": 0.15, "K": 0.77, "L": 4.03, "M": 2.41, "N": 6.75,
    "O": 7.51, "P": 1.93, "Q": 0.10, "R": 5.99, "S": 6.33, "T": 9.06, "U": 2.76,
    "V": 0.98, "W": 2.36, "X": 0.15, "Y": 1.97, "Z": 0.07,
}


def caesar_bruteforce(ciphertext):
    """Try all 26 shifts. Returns list of (shift, plaintext_guess)."""
    return [(s, caesar_decrypt(ciphertext, s)) for s in range(26)]


def letter_frequency(text):
    """Return list of (letter, count, percent) sorted by count, descending."""
    letters = _letters_only(text)
    total = len(letters) or 1
    counts = Counter(letters)
    return [(ch, n, round(100 * n / total, 2)) for ch, n in counts.most_common()]


def caesar_frequency_attack(ciphertext):
    """
    Guess the Caesar shift using chi-squared against English letter frequencies.
    Returns (best_shift, plaintext_guess). Needs a reasonably long ciphertext.
    """
    letters = _letters_only(ciphertext)
    if not letters:
        raise ValueError("Ciphertext has no letters")
    best_shift, best_score = 0, float("inf")
    for shift in range(26):
        decoded = _letters_only(caesar_decrypt(letters, shift))
        counts = Counter(decoded)
        n = len(decoded)
        score = sum(
            (counts.get(ch, 0) - n * ENGLISH_FREQ[ch] / 100) ** 2 / (n * ENGLISH_FREQ[ch] / 100)
            for ch in ALPHA
        )
        if score < best_score:
            best_shift, best_score = shift, score
    return best_shift, caesar_decrypt(ciphertext, best_shift)
