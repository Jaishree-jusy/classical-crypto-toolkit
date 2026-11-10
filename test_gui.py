"""
Headless GUI smoke test: builds the real window, fills in the widgets and presses
the real handlers. Run with a virtual display:

    xvfb-run -a python3 test_gui.py
"""
import os
import tempfile
import time

import app as appmod
from app import App, get, put, set_entry

import hashing

SAMPLE = ("Cryptography is the practice of securing information so that only the intended people can "
          "read it. Long before computers existed, armies and governments used simple ciphers to protect "
          "their messages, and just as quickly, clever people found ways to break those ciphers. The "
          "weakness of a simple substitution cipher is that every letter is always replaced by the same "
          "letter, so the pattern of the language shows through.")

a = App()
a.update()


def wait_status(prefix_not="Running", timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        a.update()
        time.sleep(0.05)
        if not a.status_label.cget("text").startswith(("Running", "Searching", "Reading")):
            return
    raise SystemExit("timed out waiting for background work")


def err():
    return a.status_label.cget("fg") == "#b00020"


# substitution: encrypt -> clear key knowledge -> break without key
put(a.sub_in, SAMPLE)
a.sub_encrypt()
cipher = get(a.sub_out)
assert cipher != SAMPLE and not err()
real_key = a.sub_key.get()
put(a.sub_in, cipher)
a.sub_decrypt()
assert get(a.sub_out) == SAMPLE
set_entry(a.sub_key, "NOTAKEY")
a.guard(a.sub_decrypt)
assert err()                                    # bad key is reported, no crash
a.sub_attack()
wait_status()
assert get(a.sub_out) == SAMPLE, get(a.sub_out)
assert a.sub_key.get() == real_key
a.sub_freq()
assert "Letter  Count" in get(a.sub_out)

# transposition
put(a.tr_in, "WE ARE DISCOVERED FLEE AT ONCE")
a.tr_encrypt()
enc = get(a.tr_out)
put(a.tr_in, enc)
a.tr_decrypt()
assert get(a.tr_out) == "WE ARE DISCOVERED FLEE AT ONCE"
put(a.tr_in, "WE ARE DISCOVERED")
a.tr_grid()
assert "ZEBRAS" in get(a.tr_out).replace("  ", "")

# one-time pad
put(a.otp_in, "Attack at dawn")
a.otp_genkey()
a.otp_encrypt()
ct = get(a.otp_out)
put(a.otp_in, ct)
a.otp_decrypt()
assert get(a.otp_out) == "ATTACK AT DAWN"

# otp reuse
a.ru_run()
assert "YES" in get(a.ru_out)
a.ru_drag()
assert "SENDMORE" in get(a.ru_drag_out)
a.ru_which.current(1)
set_entry(a.ru_crib, "SENDMORE")
a.ru_drag()
assert "MEETMEAT" in get(a.ru_drag_out)

# hash
put(a.h_in, "abc")
a.h_hash_text()
assert "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" in get(a.h_out)
a.h_hmac_text()
assert "HMAC-SHA256" in get(a.h_out)
a.h_avalanche()
assert "output bits changed" in get(a.h_out)

# integrity checker on a real temp file
with tempfile.TemporaryDirectory() as d:
    p = os.path.join(d, "file.txt")
    open(p, "w").write("hello integrity\n")
    set_entry(a.i_file, p)
    set_entry(a.i_key, "k3y")
    a.i_create()
    a.i_verify()
    assert "FILE IS UNCHANGED" in get(a.i_out), get(a.i_out)
    open(p, "a").write("tampered")
    a.i_verify()
    assert "MODIFIED" in get(a.i_out) and err()
    open(p, "w").write("hello integrity\n")
    set_entry(a.i_key, "wrong")
    a.i_verify()
    assert "MODIFIED" in get(a.i_out)
a.i_sample()
assert os.path.isfile(a.i_file.get())
os.remove(a.i_file.get())

# birthday
a.b_bits.set(20)
a.b_run()
wait_status()
assert "Tries needed" in get(a.b_out), get(a.b_out)
a.b_bits.set(99)
a.guard(a.b_run)
assert err()

# other ciphers
for name, key, text in [("Caesar", "3", "HELLO"), ("Vigenere", "LEMON", "ATTACKATDAWN"),
                        ("Playfair", "MONARCHY", "INSTRUMENTS"), ("Hill (2x2)", "3 3 2 5", "HELP"),
                        ("Rail Fence", "3", "WEAREDISCOVEREDFLEEATONCE")]:
    a.oc_cipher.set(name)
    set_entry(a.oc_key, key)
    put(a.oc_in, text)
    a.oc_apply(True)
    enc = get(a.oc_out)
    assert enc != text and not err(), name
    put(a.oc_in, enc)
    a.oc_apply(False)
    assert get(a.oc_out).startswith(text[:-1]), (name, get(a.oc_out))
a.oc_cipher.set("Caesar")
set_entry(a.oc_key, "abc")
a.guard(lambda: a.oc_apply(True))
assert err()
put(a.oc_in, "KHOOR ZRUOG")
a.oc_brute()
assert "shift  3: HELLO WORLD" in get(a.oc_out)
put(a.oc_in, SAMPLE)
a.oc_cipher.set("Caesar")
set_entry(a.oc_key, "5")
a.oc_apply(True)
put(a.oc_in, get(a.oc_out))
a.oc_freq()
assert "Most likely shift: 5" in get(a.oc_out)

a.destroy()
print("GUI SMOKE TEST PASSED")
