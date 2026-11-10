import os
import tempfile
import time

import hashing
import otp
import substitution as sub
import transposition as tr

SAMPLE = (
    "Cryptography is the practice of securing information so that only the intended people "
    "can read it. Long before computers existed, armies and governments used simple ciphers "
    "to protect their messages, and just as quickly, clever people found ways to break those "
    "ciphers. The weakness of a simple substitution cipher is that every letter is always "
    "replaced by the same letter, so the pattern of the language shows through. An attacker "
    "who counts how often each letter appears can guess the most common letters and then use "
    "common words to fix the rest of the key. This is why modern systems depend on much "
    "stronger mathematics and on keys that are long and truly random."
)

# ------------------------------------------------ substitution
key = sub.generate_key()
assert sorted(key) == list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
ct = sub.substitution_encrypt(SAMPLE, key)
assert sub.substitution_decrypt(ct, key) == SAMPLE
assert sub.substitution_encrypt("Hello, World!", sub.keyword_key("zebras"))[5] == ","
assert sub.keyword_key("ZEBRAS").startswith("ZEBRAS")
for bad in ["ABC", "A" * 26, ""]:
    try:
        sub.validate_key(bad)
        raise SystemExit("bad key accepted")
    except ValueError:
        pass

# attack: several random keys, measure how many letters come back right
results = []
for seed in range(5):
    k = sub.generate_key(__import__("random").Random(seed))
    c = sub.substitution_encrypt(SAMPLE, k)
    t0 = time.time()
    rk, guess, _ = sub.substitution_attack(c, seed=1)
    secs = time.time() - t0
    orig = [ch for ch in SAMPLE.upper() if ch.isalpha()]
    got = [ch for ch in guess.upper() if ch.isalpha()]
    acc = sum(a == b for a, b in zip(orig, got)) / len(orig)
    results.append(acc)
    print(f"  substitution attack seed {seed}: {acc:.1%} letters correct, {secs:.1f}s")
assert min(results) >= 0.90, results

# ------------------------------------------------ double transposition
for text in [SAMPLE, "Hello", "A", "", "short msg!", "x" * 101]:
    for k1, k2 in [("ZEBRA", "STRIPES"), ("AB", "CD"), ("security", "key"), ("AAAA", "BBBB")]:
        enc = tr.double_transposition_encrypt(text, k1, k2)
        assert sorted(enc) == sorted(text)          # same letters, only rearranged
        assert tr.double_transposition_decrypt(enc, k1, k2) == text, (text, k1, k2)
assert tr.columnar_encrypt("WEAREDISCOVEREDFLEEATONCE", "ZEBRAS") == "EVLNACDTESEAROFODEECWIREE"
assert tr.columnar_decrypt("EVLNACDTESEAROFODEECWIREE", "ZEBRAS") == "WEAREDISCOVEREDFLEEATONCE"
try:
    tr.columnar_encrypt("abc", "A")
    raise SystemExit("short key accepted")
except ValueError:
    pass

# ------------------------------------------------ one-time pad
msg = "Attack at dawn, 5 o'clock!"
k = otp.generate_key(30)
c = otp.otp_encrypt(msg, k)
assert otp.otp_decrypt(c, k) == msg.upper()
assert otp.otp_encrypt("HELLO", "XMCKL") == "EQNVZ"   # textbook example
try:
    otp.otp_encrypt("LONG MESSAGE", "ABC")
    raise SystemExit("short key accepted")
except ValueError:
    pass
assert len(set(otp.generate_key(200))) > 15            # key is not constant

demo = otp.reuse_demo("MEET ME AT THE OLD BRIDGE AT NOON", "SEND MORE MONEY TO THE SAFE HOUSE")
assert demo["same"]                                    # key cancels out
hits = otp.crib_drag(demo["c1"], demo["c2"], "MEETMEAT", which="p1")
assert hits[0][1] == demo["p2"][:8], hits[0]           # crib at the right spot reveals message 2
hits2 = otp.crib_drag(demo["c1"], demo["c2"], "SENDMORE", which="p2")
assert hits2[0][1] == demo["p1"][:8], hits2[0]

# ------------------------------------------------ hashing
assert hashing.hash_text("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
assert hashing.hash_text("abc", "md5") == "900150983cd24fb0d6963f7d28e17f72"
assert hashing.hash_text("abc", "sha1") == "a9993e364706816aba3e25717850c26c9cd0d89d"
assert hashing.hmac_text("The quick brown fox jumps over the lazy dog", "key") == \
    "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
for algo in hashing.ALGORITHMS:
    assert len(hashing.hash_text("x", algo)) > 30

a = hashing.avalanche("hello world", "hello worle")
assert 35 <= a["percent"] <= 65, a

with tempfile.TemporaryDirectory() as d:
    f = os.path.join(d, "data.txt")
    with open(f, "w") as fh:
        fh.write("original contents\n" * 1000)
    assert hashing.hash_file(f) == hashing.hash_text("original contents\n" * 1000)
    rec = hashing.create_record(f, "sha256", key="s3cret")
    rp = f + ".integrity.json"
    hashing.save_record(rec, rp)
    rec = hashing.load_record(rp)
    ok, det = hashing.check_record(f, rec, key="s3cret")
    assert ok and det["hash_ok"] and det["hmac_ok"]
    ok, det = hashing.check_record(f, rec, key="wrong")       # wrong key -> HMAC fails
    assert not ok and det["hash_ok"] and det["hmac_ok"] is False
    with open(f, "a") as fh:                                  # tamper with the file
        fh.write("!")
    ok, det = hashing.check_record(f, rec, key="s3cret")
    assert not ok and not det["hash_ok"] and not det["hmac_ok"]

for bits in (8, 16, 24):
    r = hashing.birthday_attack(bits)
    assert r["message1"] != r["message2"]
    assert hashing._truncated(r["message1"], bits, "sha256") == hashing._truncated(r["message2"], bits, "sha256")
    print(f"  birthday attack {bits} bits: collision after {r['tries']} tries (expected ~{r['expected']}, brute force {r['brute_force_needed']})")
t0 = time.time()
r = hashing.birthday_attack(32)
print(f"  birthday attack 32 bits: {r['tries']} tries in {time.time() - t0:.1f}s")

print("ALL TOOLKIT TESTS PASSED")
