"""
Double Transposition Cipher   (VTU BIS703, Module 1)

A columnar transposition does not change the letters, it only rearranges them:
the text is written in rows under a keyword, then the columns are read out in the
alphabetical order of the keyword letters. Double transposition does this twice
with two different keywords, which hides the pattern much better than one pass.

No padding is added, so decryption gives back the exact original text.
"""


def _column_order(key):
    key = "".join(c for c in key.upper() if c.isalpha())
    if len(key) < 2:
        raise ValueError("Key must contain at least 2 letters.")
    # Columns are read in alphabetical order of the key letters (ties: left to right).
    return key, sorted(range(len(key)), key=lambda i: (key[i], i))


def columnar_encrypt(text, key):
    key, order = _column_order(key)
    k = len(key)
    return "".join(text[c::k] for c in order)


def columnar_decrypt(text, key):
    key, order = _column_order(key)
    k, n = len(key), len(text)
    out = [""] * n
    pos = 0
    for c in order:
        length = len(range(c, n, k))
        out[c::k] = list(text[pos:pos + length])
        pos += length
    return "".join(out)


def double_transposition_encrypt(text, key1, key2):
    return columnar_encrypt(columnar_encrypt(text, key1), key2)


def double_transposition_decrypt(text, key1, key2):
    return columnar_decrypt(columnar_decrypt(text, key2), key1)


def transposition_grid(text, key):
    """Text-table of the first pass (for display / report). '_' marks a space."""
    key, order = _column_order(key)
    k = len(key)
    rank = {col: n + 1 for n, col in enumerate(order)}
    lines = ["  ".join(key), "  ".join(str(rank[i]) for i in range(k)), "-" * (3 * k - 2)]
    shown = text.replace(" ", "_")
    for i in range(0, len(shown), k):
        lines.append("  ".join(shown[i:i + k]))
    return "\n".join(lines)
