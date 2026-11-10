"""
Hash functions, HMAC, integrity checking and the birthday attack   (VTU BIS703, Module 2)

Everything here uses Python's standard library (hashlib / hmac / secrets).
Note: Tiger hash (named in the syllabus) is not available in hashlib, so SHA-2 / SHA-3
are used as the modern examples; MD5 and SHA-1 are kept to show weaker, older hashes.
"""

import hashlib
import hmac
import json
import math
import os
import secrets
from datetime import datetime

ALGORITHMS = ["md5", "sha1", "sha256", "sha512", "sha3_256"]
_CHUNK = 1024 * 1024


def _new(algo):
    if algo not in ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algo}")
    return hashlib.new(algo)


# ---------------------------------------------------------------- plain hashes
def hash_text(text, algo="sha256"):
    h = _new(algo)
    h.update(text.encode("utf-8"))
    return h.hexdigest()


def hash_file(path, algo="sha256"):
    h = _new(algo)
    with open(path, "rb") as f:
        while True:
            block = f.read(_CHUNK)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


# ---------------------------------------------------------------- HMAC
def hmac_text(text, key, algo="sha256"):
    if algo not in ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algo}")
    return hmac.new(key.encode("utf-8"), text.encode("utf-8"), algo).hexdigest()


def hmac_file(path, key, algo="sha256"):
    if algo not in ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algo}")
    h = hmac.new(key.encode("utf-8"), digestmod=algo)
    with open(path, "rb") as f:
        while True:
            block = f.read(_CHUNK)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def same_digest(a, b):
    """Constant-time comparison of two hex digests."""
    return hmac.compare_digest(a.strip().lower(), b.strip().lower())


# ---------------------------------------------------------------- integrity checker
def create_record(path, algo="sha256", key=None):
    """Baseline record of a file: its hash and (optionally) its HMAC. Save it with save_record()."""
    rec = {
        "file": os.path.basename(path),
        "size_bytes": os.path.getsize(path),
        "algorithm": algo,
        "hash": hash_file(path, algo),
        "hmac": hmac_file(path, key, algo) if key else None,
        "created": datetime.now().isoformat(timespec="seconds"),
    }
    return rec


def save_record(record, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)


def load_record(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def check_record(path, record, key=None):
    """
    Compare a file against a saved record.
    Returns (ok, details): details says whether the hash and the HMAC match.
    The HMAC check also proves the record itself was not forged, because only
    someone with the secret key can produce a valid HMAC.
    """
    algo = record["algorithm"]
    details = {"hash_ok": same_digest(hash_file(path, algo), record["hash"]), "hmac_ok": None}
    if record.get("hmac"):
        if not key:
            details["hmac_ok"] = False
            details["note"] = "Record has an HMAC but no key was given."
        else:
            details["hmac_ok"] = same_digest(hmac_file(path, key, algo), record["hmac"])
    ok = details["hash_ok"] and details["hmac_ok"] in (None, True)
    return ok, details


# ---------------------------------------------------------------- avalanche effect
def avalanche(text1, text2, algo="sha256"):
    """How many output bits change when the input changes slightly?"""
    d1 = bytes.fromhex(hash_text(text1, algo))
    d2 = bytes.fromhex(hash_text(text2, algo))
    diff = sum(bin(a ^ b).count("1") for a, b in zip(d1, d2))
    total = len(d1) * 8
    return {"hash1": d1.hex(), "hash2": d2.hex(), "bits_changed": diff,
            "total_bits": total, "percent": round(100 * diff / total, 1)}


# ---------------------------------------------------------------- birthday attack
def _truncated(msg, bits, algo):
    digest = hashlib.new(algo, msg.encode("utf-8")).digest()
    value = int.from_bytes(digest, "big")
    return value >> (len(digest) * 8 - bits)


def birthday_attack(bits=24, algo="sha256", max_tries=None):
    """
    Find two different messages whose hashes agree in the first `bits` bits.
    A hash with n output bits needs about 2^(n/2) tries to collide (not 2^n),
    which is the birthday paradox. Returns a dict with the colliding messages.
    """
    if not 8 <= bits <= 40:
        raise ValueError("Choose between 8 and 40 bits (40 may take a few seconds).")
    limit = max_tries or int(60 * 2 ** (bits / 2))
    prefix = secrets.token_hex(4)
    seen = {}
    for i in range(limit):
        msg = f"{prefix}-{i}"
        h = _truncated(msg, bits, algo)
        if h in seen:
            width = (bits + 3) // 4
            return {"message1": seen[h], "message2": msg, "bits": bits,
                    "truncated_hash": format(h, f"0{width}x"), "tries": i + 1,
                    "expected": round(1.2533 * 2 ** (bits / 2)),
                    "brute_force_needed": 2 ** bits}
        seen[h] = msg
    return None
