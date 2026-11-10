# Classical Cryptography & Hash Toolkit

**Mini project - BIS703 Information and Network Security (VTU, 7th semester)**

A desktop application (Python + Tkinter) that implements the classical ciphers from Module 1 of the syllabus, the hash-function topics from Module 2, and shows how each of them can be **attacked**. Everything is real working code - nothing is simulated or hard-coded. No extra packages are needed, only Python.

---

## 1. What the project does

| Tab in the app | What it demonstrates | Syllabus topic |
|---|---|---|
| **Substitution** | Encrypt / decrypt with a 26-letter key, and **break the cipher without the key** using frequency analysis | Simple substitution cipher, cryptanalysis of a simple substitution (Module 1) |
| **Double Transposition** | Two rounds of columnar transposition with two keywords, with a grid view | Double transposition cipher (Module 1) |
| **One-Time Pad** | Encrypt / decrypt with a random key, key generator | One-time pad (Module 1) |
| **OTP Reuse Attack** | Shows why a pad key must never be reused, and recovers text with a "crib drag" | One-time pad, Project VENONA (Module 1) |
| **Hash & HMAC** | MD5, SHA-1, SHA-256, SHA-512, SHA3-256 of text or files; HMAC; avalanche effect | Hash function, HMAC, uses of hash functions (Module 2) |
| **Integrity Checker** | Save a baseline (hash + HMAC) of a file and later detect any change | Uses of hash functions, HMAC (Module 2) |
| **Birthday Attack** | Finds a real hash collision on a shortened hash and compares it with theory | The birthday problem (Module 2) |
| **Other Ciphers** | Caesar, Vigenere, Playfair, Hill (2x2), Rail Fence + Caesar brute force and frequency attack | Classic crypto (Module 1) - extra |

Every tab has a **Clear** button next to its other buttons. It empties the text boxes so you can start a new example without pressing Ctrl+A and Backspace. Keys and settings you typed are kept (the Integrity Checker tab also clears the file path).

### Course outcomes covered
- **CO1** - understand basic concepts of security and cryptography (all Module 1 tabs)
- **CO2** - apply different hash functions (Hash & HMAC, Integrity Checker, Birthday Attack)
- CO3 to CO5 (random numbers, protocols, key management, applications) are theory topics; the One-Time Pad tab uses Python's `secrets` module, which is a cryptographically secure random number generator (Module 3 topic: random number generation).

> Note: Tiger hash is named in the syllabus but is not available in Python's standard library, so SHA-2 / SHA-3 are used as the modern examples, and MD5 / SHA-1 show older, weaker hashes.

---

## 2. Files

```
crypto_toolkit/
  app.py            the GUI (run this file)
  ciphers.py        Caesar, Vigenere, Playfair, Hill, Rail Fence + Caesar attacks + letter frequency
  substitution.py   substitution cipher + automatic attack
  transposition.py  columnar and double transposition
  otp.py            one-time pad + key-reuse attack (crib drag)
  hashing.py        hashes, HMAC, integrity records, avalanche, birthday attack
  test_ciphers.py   tests for ciphers.py
  test_toolkit.py   tests for the other modules
  test_gui.py       tests that press the real GUI buttons (needs a display)
  README.md         this file
```

The logic (`ciphers.py`, `substitution.py`, `transposition.py`, `otp.py`, `hashing.py`) is completely separate from the window (`app.py`), so every algorithm can also be used or tested without the GUI.

---

## 3. How to run

1. Install **Python 3.8 or newer** (python.org). On Windows the installer includes Tkinter. On Ubuntu/Debian: `sudo apt install python3-tk`.
2. Put all the files in one folder.
3. Open a terminal in that folder and run:

```
python app.py
```
(on Linux/Mac use `python3 app.py`)

To run the tests:

```
python test_ciphers.py
python test_toolkit.py
```

Both should end with `... PASSED`. (`test_gui.py` needs a screen; on Linux without one use `xvfb-run -a python3 test_gui.py`.)

---

## 4. Quick tour - try these in the app

**Substitution tab (the main demo)**
1. Paste any English paragraph (at least 150 letters) in *Input text* and press **Encrypt**. The text is scrambled using the key shown.
2. Copy the output back into *Input text*, then press **Break without key**. The program recovers the key and the original text by itself, and fills in the key box.
3. **Letter frequencies** shows why this works: in English E, T, A, O are the most common, and a substitution cipher keeps that pattern.

**One-Time Pad + OTP Reuse Attack**
1. In *One-Time Pad*, type a message, press **Generate key**, then **Encrypt**.
2. In *OTP Reuse Attack*, press **Encrypt both with the SAME key**. The (C1 - C2) line is identical to the (P1 - P2) line, so the key has cancelled out.
3. Press **Drag crib**. Using the guess `MEETMEAT` for message 1, the first position reveals `SENDMORE` of message 2.

**Hash & HMAC**: type `abc` and press **Hash text** with SHA-256 - the result starts with `ba7816bf8f01cfea`, the standard test value. **Avalanche demo** shows about 50% of output bits changing for a one-letter change.

**Integrity Checker**: press **Create a sample file to try**, then **Create baseline record**. Open `sample_file.txt` in Notepad, change one letter, save, and press **Verify file** - it reports that the file was modified.

**Birthday Attack**: with 24 bits it finds two different messages with the same hash after roughly 5,000 tries instead of 16 million.

**Known-answer examples for the *Other Ciphers* tab** (to check your understanding)
| Cipher | Key | Plaintext | Ciphertext |
|---|---|---|---|
| Caesar | 3 | HELLO | KHOOR |
| Vigenere | LEMON | ATTACKATDAWN | LXFOPVEFRNHR |
| Playfair | MONARCHY | INSTRUMENTS | GATLMZCLRQXA |
| Hill 2x2 | 3 3 2 5 | HELP | HIAT |
| Rail Fence | 3 | WEAREDISCOVEREDFLEEATONCE | WECRLTEERDSOEEFEAOCAIVDEN |

---

## 5. How each part works

**Simple substitution.** The key is a shuffled alphabet. Plaintext letter *A* becomes `key[0]`, *B* becomes `key[1]` and so on. There are 26! (about 4 x 10^26) keys, so brute force is impossible - but the cipher is still weak because letter frequencies survive.

**Attack on substitution** (`substitution.py`):
1. *Frequency analysis* - count the cipher letters and match them, most common first, to English letters (E, T, A, O ...). This gives a rough first guess.
2. *Hill climbing* - repeatedly swap two letters of the guessed key. After each swap the decrypted text is scored by how English-like it is (single-letter, two-letter and three-letter frequencies such as TH, HE, THE, ING). A swap is kept only if the score improves.
3. The search is restarted from small random changes, and the best result is returned.

**Double transposition.** Write the text in rows under a keyword, then read the columns in alphabetical order of the keyword letters. Doing this twice with two keywords mixes the positions much more. Letters never change, only their positions. No padding is added, so decryption gives back the exact original text.

**One-time pad.** `C = (P + K) mod 26` and `P = (C - K) mod 26`. It is perfectly secret only when the key is truly random, as long as the message, and used only once. The key is generated with `secrets.choice` (cryptographically secure).

**Key reuse attack.** If two messages use the same key, `C1 - C2 = (P1 + K) - (P2 + K) = P1 - P2`. The key disappears. If you guess a word of one message (a crib) and slide it along, the other message appears wherever the guess is right. This kind of key reuse is how Project VENONA broke Soviet messages.

**Hash and HMAC.** A hash maps any input to a fixed-size fingerprint; the same input always gives the same output, and any change gives a completely different output (avalanche effect). HMAC mixes a secret key into the hash, so only a person who knows the key can create or verify it - this protects against someone changing both the file *and* its stored hash.

**Birthday attack.** With an n-bit hash, a collision is expected after about 1.25 x 2^(n/2) tries (not 2^n), as in the birthday paradox. The app cuts SHA-256 down to n bits so a collision can be found in seconds, and prints the real number of tries next to the theoretical value. Full 256-bit hashes would need about 2^128 tries.

---

## 6. Testing and honest limitations

All tests pass: known textbook values for each cipher, round-trip checks, hash and HMAC test vectors, tamper detection on a real file, a real birthday collision, and a headless run of the actual GUI.

- **The substitution attack needs enough text.** Measured on English text with random keys: 100 letters gave about 63% of letters correct, 150 letters about 93%, 200 letters about 99%, and 300+ letters about 100%. Very short ciphertexts do not contain enough statistics - this is a property of the method, not a bug.
- **The attack assumes English text.** Other languages or heavy abbreviations will give poor results.
- **Playfair** treats J as I and adds filler X letters, so decryption may show an extra X - this is how the cipher is defined.
- **One-time pad output is in capital letters** and only letters are encrypted; digits and punctuation are copied unchanged.
- **Classical ciphers are for learning only.** None of them (and MD5 / SHA-1) should be used to protect real data.
- The birthday demo is limited to 36 bits in the app to keep memory use small.

---

## 7. Likely viva questions

1. **Why is a simple substitution cipher insecure even though it has 26! keys?** Because every plaintext letter always maps to the same cipher letter, so the letter frequencies of the language leak through; frequency analysis does not need to try the keys.
2. **Difference between substitution and transposition?** Substitution changes the letters and keeps their positions; transposition keeps the letters and changes their positions.
3. **Why is double transposition stronger than single?** The second pass rearranges the already rearranged text, so the simple column pattern of one keyword is no longer visible.
4. **When is the one-time pad perfectly secure?** When the key is truly random, at least as long as the message, kept secret, and never reused.
5. **What goes wrong if a pad key is used twice?** The key cancels out in C1 - C2, leaking P1 - P2, and cribs can reveal both messages (Project VENONA).
6. **What is a hash function and what are its properties?** It maps any input to a fixed-size output; it should be one-way, collision resistant, and show the avalanche effect.
7. **Difference between a hash and an HMAC?** A hash needs no key so anyone can recompute it; an HMAC needs a secret key, so it also proves who created it and cannot be forged without the key.
8. **What is the birthday problem and why does it matter for hashes?** In a group of only 23 people, two likely share a birthday. Likewise an n-bit hash collides after about 2^(n/2) tries, so hash outputs must be long (at least 256 bits for 128-bit security).
9. **Why not use MD5 or SHA-1 now?** Practical collision attacks exist for both.
10. **How does your integrity checker detect tampering?** It stores the file's hash and HMAC; if even one byte changes, the new hash differs completely, and the HMAC also stops an attacker from replacing the stored hash.
11. **How does your program break the substitution cipher?** Frequency analysis for the first guess, then hill climbing with English letter, bigram and trigram scores.
12. **Where would you use these ideas today?** Hashes for file integrity and password storage, HMAC for message authentication, one-time-pad ideas in stream ciphers and key-stream generation.
