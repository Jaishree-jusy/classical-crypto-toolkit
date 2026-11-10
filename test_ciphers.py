from ciphers import *

msg = "Meet me at the old library at midnight, bring the documents."
long_msg = ("The quick brown fox jumps over the lazy dog while the sun sets slowly behind "
            "the distant hills and everyone returns home after a long day of work")

# Caesar
assert caesar_decrypt(caesar_encrypt(msg, 3), 3) == msg
assert caesar_encrypt("HELLO", 3) == "KHOOR"

# Vigenere (classic textbook example)
assert vigenere_encrypt("ATTACKATDAWN", "LEMON") == "LXFOPVEFRNHR"
assert vigenere_decrypt(vigenere_encrypt(msg, "KEY"), "KEY") == msg

# Playfair (textbook example: key MONARCHY)
assert playfair_encrypt("INSTRUMENTS", "MONARCHY") == "GATLMZCLRQXA"
assert playfair_decrypt("GATLMZCLRQXA", "MONARCHY") == "INSTRUMENTSX"

# Hill (key GYBN, plaintext ACT -> POH classic is 3x3; check 2x2 round trip)
c = hill_encrypt("HELP", "3 3 2 5")
assert hill_decrypt(c, "3 3 2 5") == "HELP", c
assert c == "HIAT", c  # textbook: HELP with key [[3,3],[2,5]] -> HIAT

# Rail fence
assert railfence_encrypt("WEAREDISCOVEREDFLEEATONCE", 3) == "WECRLTEERDSOEEFEAOCAIVDEN"
assert railfence_decrypt("WECRLTEERDSOEEFEAOCAIVDEN", 3) == "WEAREDISCOVEREDFLEEATONCE"
assert railfence_decrypt(railfence_encrypt(msg, 4), 4) == msg

# Attacks
ct = caesar_encrypt(long_msg, 11)
assert (11, long_msg) in caesar_bruteforce(ct)
shift, guess = caesar_frequency_attack(ct)
assert shift == 11 and guess == long_msg, (shift, guess)
assert letter_frequency(long_msg)[0][0] in "EOT"

# Invalid Hill key
try:
    hill_encrypt("HI", "2 4 2 4")
    raise SystemExit("expected error")
except ValueError:
    pass

print("ALL TESTS PASSED")
