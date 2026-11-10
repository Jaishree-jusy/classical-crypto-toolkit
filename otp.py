"""
One-Time Pad   (VTU BIS703, Module 1)

Each plaintext letter is shifted by the matching letter of a truly random key that
is as long as the message:   C = (P + K) mod 26    P = (C - K) mod 26

It is unbreakable ONLY if the key is random, as long as the message, and used once.
This file also shows what goes wrong when a key is reused (the "two-time pad"),
which is how Project VENONA broke Soviet messages.
"""

import secrets
import string

ALPHA = string.ascii_uppercase


def generate_key(length):
    """Cryptographically secure random key (uses the `secrets` module)."""
    if length < 1:
        raise ValueError("Length must be at least 1.")
    return "".join(secrets.choice(ALPHA) for _ in range(length))


def _clean_key(key):
    return "".join(c for c in key.upper() if c.isalpha())


def _apply(text, key, sign):
    key = _clean_key(key)
    need = sum(c.isalpha() for c in text)
    if len(key) < need:
        raise ValueError(f"Key too short: message has {need} letters but key has {len(key)}.")
    out, i = [], 0
    for ch in text.upper():
        if ch.isalpha():
            out.append(chr((ord(ch) - 65 + sign * (ord(key[i]) - 65)) % 26 + 65))
            i += 1
        else:
            out.append(ch)
    return "".join(out)


def otp_encrypt(plaintext, key):
    return _apply(plaintext, key, +1)


def otp_decrypt(ciphertext, key):
    return _apply(ciphertext, key, -1)


# ---------------------------------------------------------------- key reuse attack
def _letters(text):
    return "".join(c for c in text.upper() if c.isalpha())


def reuse_demo(plain1, plain2, key=None):
    """
    Encrypt two messages with the SAME key and show the weakness:
    (C1 - C2) mod 26 equals (P1 - P2) mod 26, so the key cancels out completely.
    Returns a dict with both ciphertexts and the two difference streams.
    """
    p1, p2 = _letters(plain1), _letters(plain2)
    n = min(len(p1), len(p2))
    if n == 0:
        raise ValueError("Both messages need at least one letter.")
    p1, p2 = p1[:n], p2[:n]
    key = _clean_key(key) if key else generate_key(n)
    if len(key) < n:
        raise ValueError("Key is shorter than the messages.")
    c1, c2 = otp_encrypt(p1, key), otp_encrypt(p2, key)
    diff_c = "".join(chr((ord(a) - ord(b)) % 26 + 65) for a, b in zip(c1, c2))
    diff_p = "".join(chr((ord(a) - ord(b)) % 26 + 65) for a, b in zip(p1, p2))
    return {"p1": p1, "p2": p2, "key": key[:n], "c1": c1, "c2": c2,
            "diff_cipher": diff_c, "diff_plain": diff_p, "same": diff_c == diff_p}


def crib_drag(c1, c2, crib, which="p1"):
    """
    Attack on key reuse WITHOUT knowing the key. Slide a guessed word (crib) along
    one message; at every position the other message's letters are revealed.
    Positions that give readable English show the crib is in the right place.

    which="p1": the crib is a guess for message 1, output shows message 2 at that spot.
    which="p2": the crib is a guess for message 2, output shows message 1 at that spot.
    Returns a list of (position, revealed_text).
    """
    c1, c2, crib = _letters(c1), _letters(c2), _letters(crib)
    n = min(len(c1), len(c2))
    if not crib or len(crib) > n:
        raise ValueError("Crib must be non-empty and not longer than the messages.")
    diff = [(ord(a) - ord(b)) % 26 for a, b in zip(c1[:n], c2[:n])]  # = P1 - P2
    results = []
    for pos in range(n - len(crib) + 1):
        seg = []
        for j, ch in enumerate(crib):
            v = ord(ch) - 65
            d = diff[pos + j]
            seg.append(chr((v - d) % 26 + 65) if which == "p1" else chr((v + d) % 26 + 65))
        results.append((pos, "".join(seg)))
    return results
