"""
Classical Cryptography & Hash Toolkit  -  VTU BIS703 (Information and Network Security)
Run:  python app.py        (needs only Python 3 with Tkinter, no extra packages)
"""

import json
import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, ttk

import ciphers
import hashing
import otp
import substitution as sub
import transposition as tr

MONO = ("Courier New", 10)


def get(box):
    return box.get("1.0", "end-1c")


def put(box, text):
    box.delete("1.0", "end")
    box.insert("1.0", text)


def set_entry(entry, text):
    entry.delete(0, "end")
    entry.insert(0, text)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Classical Cryptography & Hash Toolkit")
        self.geometry("1080x740")
        self.minsize(900, 620)

        self.status_label = tk.Label(self, text="Ready", anchor="w", padx=10, pady=4, fg="#1a5c1a")
        self.status_label.pack(side="bottom", fill="x")

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=8)
        self.reuse = None  # state for the OTP reuse tab

        for title, builder in [
            ("Substitution", self.build_substitution),
            ("Double Transposition", self.build_transposition),
            ("One-Time Pad", self.build_otp),
            ("OTP Reuse Attack", self.build_reuse),
            ("Hash & HMAC", self.build_hash),
            ("Integrity Checker", self.build_integrity),
            ("Birthday Attack", self.build_birthday),
            ("Other Ciphers", self.build_other),
        ]:
            frame = ttk.Frame(self.notebook, padding=10)
            self.notebook.add(frame, text=title)
            builder(frame)

    # ------------------------------------------------------------ small helpers
    def set_status(self, message, error=False):
        self.status_label.config(text=message, fg="#b00020" if error else "#1a5c1a")

    def guard(self, fn):
        """Run fn; show any error in the status bar instead of crashing."""
        try:
            fn()
        except (ValueError, OSError, KeyError) as e:
            self.set_status(f"Error: {e}", error=True)

    def run_async(self, work, done, busy_message, button=None):
        """Run slow work in a thread so the window stays responsive."""
        self.set_status(busy_message)
        if button is not None:
            button.config(state="disabled")
        results = queue.Queue()

        def target():
            try:
                results.put((True, work()))
            except Exception as e:  # noqa: BLE001 - report anything to the user
                results.put((False, e))

        threading.Thread(target=target, daemon=True).start()

        def poll():
            try:
                ok, value = results.get_nowait()
            except queue.Empty:
                self.after(80, poll)
                return
            if button is not None:
                button.config(state="normal")
            if ok:
                done(value)
            else:
                self.set_status(f"Error: {value}", error=True)

        self.after(80, poll)

    def box(self, parent, label, height=6):
        ttk.Label(parent, text=label).pack(anchor="w", pady=(8, 2))
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        text = tk.Text(frame, height=height, wrap="word", font=MONO, undo=True)
        scroll = ttk.Scrollbar(frame, command=text.yview)
        text.config(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        text.pack(side="left", fill="both", expand=True)
        return text

    def entry(self, parent, label, width=40, default=""):
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=3)
        ttk.Label(row, text=label, width=22).pack(side="left")
        e = ttk.Entry(row, width=width)
        e.pack(side="left", padx=6)
        if default:
            e.insert(0, default)
        return e

    def buttons(self, parent, items):
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=6)
        made = []
        for label, command in items:
            b = ttk.Button(row, text=label, command=lambda c=command: self.guard(c))
            b.pack(side="left", padx=(0, 8))
            made.append(b)
        return made

    def note(self, parent, text):
        ttk.Label(parent, text=text, foreground="#555555", wraplength=1000, justify="left").pack(anchor="w")

    def clear(self, *widgets, focus=None):
        """Empty the given text boxes / entry fields and put the cursor in `focus`."""
        for w in widgets:
            if isinstance(w, tk.Text):
                w.delete("1.0", "end")
            else:
                w.delete(0, "end")
        if focus is not None:
            focus.focus_set()
        self.set_status("Cleared.")

    # ------------------------------------------------------------ 1. substitution
    def build_substitution(self, f):
        self.note(f, "Simple substitution: every letter is replaced by one fixed letter. The key is a shuffled alphabet. "
                     "'Break without key' uses frequency analysis + hill climbing and needs about 150+ letters of English.")
        self.sub_key = self.entry(f, "Key (26 letters):", 40, sub.generate_key())
        kw = ttk.Frame(f)
        kw.pack(fill="x", pady=3)
        ttk.Label(kw, text="Keyword (optional):", width=22).pack(side="left")
        self.sub_kw = ttk.Entry(kw, width=20)
        self.sub_kw.pack(side="left", padx=6)
        ttk.Button(kw, text="Make key from keyword",
                   command=lambda: self.guard(lambda: set_entry(self.sub_key, sub.keyword_key(self.sub_kw.get())))
                   ).pack(side="left", padx=6)
        ttk.Button(kw, text="Random key",
                   command=lambda: set_entry(self.sub_key, sub.generate_key())).pack(side="left")
        self.sub_in = self.box(f, "Input text", 7)
        btns = self.buttons(f, [
            ("Encrypt", self.sub_encrypt),
            ("Decrypt", self.sub_decrypt),
            ("Break without key", self.sub_attack),
            ("Letter frequencies", self.sub_freq),
            ("Clear", lambda: self.clear(self.sub_in, self.sub_out, focus=self.sub_in)),
        ])
        self.sub_attack_btn = btns[2]
        self.sub_out = self.box(f, "Output", 7)

    def sub_encrypt(self):
        put(self.sub_out, sub.substitution_encrypt(get(self.sub_in), self.sub_key.get()))
        self.set_status("Encrypted.")

    def sub_decrypt(self):
        put(self.sub_out, sub.substitution_decrypt(get(self.sub_in), self.sub_key.get()))
        self.set_status("Decrypted.")

    def sub_freq(self):
        rows = ciphers.letter_frequency(get(self.sub_in))
        if not rows:
            raise ValueError("Type or paste some text in the input box first.")
        lines = ["Letter  Count  Percent"]
        lines += [f"  {ch}     {n:5d}  {p:6.2f}%  " + "#" * int(p * 2) for ch, n, p in rows]
        lines.append("\nMost common letters in English: E T A O I N S R H L")
        put(self.sub_out, "\n".join(lines))
        self.set_status("Letter frequencies of the input text.")

    def sub_attack(self):
        ciphertext = get(self.sub_in)

        def done(result):
            key, guess, _ = result
            set_entry(self.sub_key, key)
            put(self.sub_out, guess)
            self.set_status("Attack finished. Recovered key is in the key box. "
                            "If a few words look wrong, the ciphertext was probably too short.")

        self.run_async(lambda: sub.substitution_attack(ciphertext), done,
                       "Running frequency analysis and hill climbing ...", self.sub_attack_btn)

    # ------------------------------------------------------------ 2. double transposition
    def build_transposition(self, f):
        self.note(f, "Columnar transposition twice with two keywords. Letters are only rearranged, never changed. "
                     "Spaces and punctuation are rearranged too, so decryption restores the text exactly.")
        self.tr_k1 = self.entry(f, "Key 1 (letters):", 25, "ZEBRAS")
        self.tr_k2 = self.entry(f, "Key 2 (letters):", 25, "STRIPES")
        self.tr_in = self.box(f, "Input text", 7)
        self.buttons(f, [("Encrypt", self.tr_encrypt), ("Decrypt", self.tr_decrypt),
                         ("Show grid of 1st pass", self.tr_grid),
                         ("Clear", lambda: self.clear(self.tr_in, self.tr_out, focus=self.tr_in))])
        self.tr_out = self.box(f, "Output", 8)

    def tr_encrypt(self):
        put(self.tr_out, tr.double_transposition_encrypt(get(self.tr_in), self.tr_k1.get(), self.tr_k2.get()))
        self.set_status("Encrypted.")

    def tr_decrypt(self):
        put(self.tr_out, tr.double_transposition_decrypt(get(self.tr_in), self.tr_k1.get(), self.tr_k2.get()))
        self.set_status("Decrypted.")

    def tr_grid(self):
        put(self.tr_out, tr.transposition_grid(get(self.tr_in), self.tr_k1.get()))
        self.set_status("Row 1 = key, row 2 = the order the columns are read in. '_' is a space.")

    # ------------------------------------------------------------ 3. one-time pad
    def build_otp(self, f):
        self.note(f, "C = (P + K) mod 26. Unbreakable only if the key is truly random, as long as the message and used ONCE. "
                     "Output is in capital letters; digits and punctuation are left as they are.")
        self.otp_in = self.box(f, "Message", 6)
        self.otp_key = self.box(f, "Key (one random letter per message letter)", 3)
        self.buttons(f, [("Generate key for this message", self.otp_genkey),
                         ("Encrypt", self.otp_encrypt), ("Decrypt", self.otp_decrypt),
                         ("Clear", lambda: self.clear(self.otp_in, self.otp_key, self.otp_out, focus=self.otp_in))])
        self.otp_out = self.box(f, "Output", 6)

    def otp_genkey(self):
        n = sum(c.isalpha() for c in get(self.otp_in))
        put(self.otp_key, otp.generate_key(n))
        self.set_status(f"Generated a random {n}-letter key (cryptographically secure).")

    def otp_encrypt(self):
        put(self.otp_out, otp.otp_encrypt(get(self.otp_in), get(self.otp_key)))
        self.set_status("Encrypted.")

    def otp_decrypt(self):
        put(self.otp_out, otp.otp_decrypt(get(self.otp_in), get(self.otp_key)))
        self.set_status("Decrypted (type the ciphertext in the Message box).")

    # ------------------------------------------------------------ 4. OTP reuse attack
    def build_reuse(self, f):
        self.note(f, "What if the same one-time pad key is used twice? The key cancels out: (C1 - C2) = (P1 - P2). "
                     "Then guessing a word of one message (a 'crib') reveals the other message at that position - "
                     "this is how Project VENONA broke Soviet traffic.")
        self.ru_p1 = self.entry(f, "Message 1:", 60, "MEET ME AT THE OLD BRIDGE AT NOON")
        self.ru_p2 = self.entry(f, "Message 2:", 60, "SEND MORE MONEY TO THE SAFE HOUSE")
        self.buttons(f, [("Encrypt both with the SAME key", self.ru_run), ("Clear", self.ru_clear)])
        self.ru_out = self.box(f, "Result", 9)
        self.ru_crib = self.entry(f, "Guessed word (crib):", 25, "MEETMEAT")
        row = ttk.Frame(f)
        row.pack(fill="x", pady=3)
        ttk.Label(row, text="The crib belongs to:", width=22).pack(side="left")
        self.ru_which = ttk.Combobox(row, values=["Message 1", "Message 2"], state="readonly", width=14)
        self.ru_which.current(0)
        self.ru_which.pack(side="left", padx=6)
        self.buttons(f, [("Drag crib along the ciphertexts", self.ru_drag)])
        self.ru_drag_out = self.box(f, "Crib drag (readable English = correct position)", 8)

    def ru_clear(self):
        self.reuse = None
        self.clear(self.ru_p1, self.ru_p2, self.ru_crib, self.ru_out, self.ru_drag_out, focus=self.ru_p1)

    def ru_run(self):
        self.reuse = otp.reuse_demo(self.ru_p1.get(), self.ru_p2.get())
        d = self.reuse
        put(self.ru_out,
            f"Random key       : {d['key']}\n"
            f"Message 1        : {d['p1']}\nMessage 2        : {d['p2']}\n"
            f"Ciphertext 1     : {d['c1']}\nCiphertext 2     : {d['c2']}\n"
            f"(C1 - C2) mod 26 : {d['diff_cipher']}\n(P1 - P2) mod 26 : {d['diff_plain']}\n"
            f"Identical?       : {'YES - the key cancelled out completely' if d['same'] else 'NO'}")
        self.set_status("Done. An attacker sees only the two ciphertexts - try the crib drag below.")

    def ru_drag(self):
        if not self.reuse:
            raise ValueError("Run 'Encrypt both with the SAME key' first.")
        which = "p1" if self.ru_which.get() == "Message 1" else "p2"
        hits = otp.crib_drag(self.reuse["c1"], self.reuse["c2"], self.ru_crib.get(), which)
        other = "Message 2" if which == "p1" else "Message 1"
        put(self.ru_drag_out, "\n".join(f"position {p:3d}:  {t}" for p, t in hits))
        self.set_status(f"Each line shows {other} at that position if the crib is placed there.")

    # ------------------------------------------------------------ 5. hash & hmac
    def build_hash(self, f):
        self.note(f, "Hash = fixed-size fingerprint of the data. HMAC = hash + secret key, so only people with the key can "
                     "produce or check it. Avalanche: a tiny change in the input changes about half of the output bits.")
        row = ttk.Frame(f)
        row.pack(fill="x", pady=3)
        ttk.Label(row, text="Algorithm:", width=22).pack(side="left")
        self.h_algo = ttk.Combobox(row, values=hashing.ALGORITHMS, state="readonly", width=12)
        self.h_algo.set("sha256")
        self.h_algo.pack(side="left", padx=6)
        self.h_key = self.entry(f, "Secret key (for HMAC):", 30, "mysecretkey")
        self.h_text2 = self.entry(f, "Changed text (avalanche):", 40)
        self.h_in = self.box(f, "Text", 5)
        btns = self.buttons(f, [
            ("Hash text", self.h_hash_text), ("HMAC of text", self.h_hmac_text),
            ("Avalanche demo", self.h_avalanche),
            ("Hash a file ...", self.h_hash_file), ("HMAC of a file ...", self.h_hmac_file),
            ("Clear", lambda: self.clear(self.h_in, self.h_text2, self.h_out, focus=self.h_in)),
        ])
        self.h_file_btns = (btns[3], btns[4])
        self.h_out = self.box(f, "Result", 8)

    def h_hash_text(self):
        a = self.h_algo.get()
        put(self.h_out, f"{a.upper()} hash:\n{hashing.hash_text(get(self.h_in), a)}")
        self.set_status("Hash computed.")

    def h_hmac_text(self):
        a = self.h_algo.get()
        if not self.h_key.get():
            raise ValueError("Enter a secret key for the HMAC.")
        put(self.h_out, f"HMAC-{a.upper()}:\n{hashing.hmac_text(get(self.h_in), self.h_key.get(), a)}")
        self.set_status("HMAC computed.")

    def h_avalanche(self):
        t1 = get(self.h_in)
        if not t1:
            raise ValueError("Type some text first.")
        t2 = self.h_text2.get() or (t1[0].swapcase() + t1[1:])
        r = hashing.avalanche(t1, t2, self.h_algo.get())
        put(self.h_out, f"Text 1: {t1}\nHash 1: {r['hash1']}\n\nText 2: {t2}\nHash 2: {r['hash2']}\n\n"
                        f"{r['bits_changed']} of {r['total_bits']} output bits changed ({r['percent']}%).\n"
                        "A good hash changes about 50% of its bits even for a one-letter change.")
        self.set_status("Avalanche effect shown.")

    def _file_hash(self, use_hmac):
        path = filedialog.askopenfilename(title="Choose a file")
        if not path:
            return
        a, key = self.h_algo.get(), self.h_key.get()
        if use_hmac and not key:
            raise ValueError("Enter a secret key for the HMAC.")
        work = (lambda: hashing.hmac_file(path, key, a)) if use_hmac else (lambda: hashing.hash_file(path, a))
        label = f"HMAC-{a.upper()}" if use_hmac else f"{a.upper()} hash"
        self.run_async(work, lambda digest: (put(self.h_out, f"File: {path}\n{label}:\n{digest}"),
                                            self.set_status("File processed.")),
                       "Reading file ...")

    def h_hash_file(self):
        self._file_hash(False)

    def h_hmac_file(self):
        self._file_hash(True)

    # ------------------------------------------------------------ 6. integrity checker
    def build_integrity(self, f):
        self.note(f, "Create a baseline (hash + optional HMAC) of a file, save it next to the file as <name>.integrity.json, "
                     "and later verify the file against it. Any change - even one byte - is detected.")
        row = ttk.Frame(f)
        row.pack(fill="x", pady=3)
        ttk.Label(row, text="File:", width=22).pack(side="left")
        self.i_file = ttk.Entry(row, width=60)
        self.i_file.pack(side="left", padx=6)
        ttk.Button(row, text="Browse ...", command=self.i_browse).pack(side="left")
        row2 = ttk.Frame(f)
        row2.pack(fill="x", pady=3)
        ttk.Label(row2, text="Algorithm:", width=22).pack(side="left")
        self.i_algo = ttk.Combobox(row2, values=hashing.ALGORITHMS, state="readonly", width=12)
        self.i_algo.set("sha256")
        self.i_algo.pack(side="left", padx=6)
        self.i_key = self.entry(f, "Secret key (optional):", 30)
        self.buttons(f, [("Create baseline record", self.i_create), ("Verify file", self.i_verify),
                         ("Create a sample file to try", self.i_sample),
                         ("Clear", lambda: self.clear(self.i_file, self.i_out, focus=self.i_file))])
        self.i_out = self.box(f, "Result", 14)

    def i_browse(self):
        path = filedialog.askopenfilename(title="Choose a file")
        if path:
            set_entry(self.i_file, path)

    def _i_path(self):
        path = self.i_file.get().strip()
        if not path:
            raise ValueError("Choose a file first.")
        if not os.path.isfile(path):
            raise ValueError("That file does not exist.")
        return path

    def i_create(self):
        path = self._i_path()
        rec = hashing.create_record(path, self.i_algo.get(), self.i_key.get() or None)
        rec_path = path + ".integrity.json"
        hashing.save_record(rec, rec_path)
        put(self.i_out, f"Baseline saved to:\n{rec_path}\n\n" + json.dumps(rec, indent=2))
        self.set_status("Baseline record created. Edit the file, then press 'Verify file'.")

    def i_verify(self):
        path = self._i_path()
        rec_path = path + ".integrity.json"
        if not os.path.isfile(rec_path):
            raise ValueError("No baseline record found for this file. Create one first.")
        rec = hashing.load_record(rec_path)
        ok, det = hashing.check_record(path, rec, self.i_key.get() or None)
        lines = [f"File    : {path}", f"Record  : {rec_path} (created {rec.get('created', '?')})", ""]
        lines.append(f"Hash matches : {'yes' if det['hash_ok'] else 'NO'}")
        if det["hmac_ok"] is not None:
            lines.append(f"HMAC matches : {'yes' if det['hmac_ok'] else 'NO'}")
        if det.get("note"):
            lines.append(det["note"])
        if det["hash_ok"] and det["hmac_ok"] is False:
            lines.append("Hash matches but HMAC does not: wrong key, or the record file itself was altered.")
        lines += ["", "RESULT: FILE IS UNCHANGED" if ok else "RESULT: FILE HAS BEEN MODIFIED (or the key is wrong)"]
        put(self.i_out, "\n".join(lines))
        self.set_status("Verified: unchanged." if ok else "Verification FAILED.", error=not ok)

    def i_sample(self):
        folder = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(folder, "sample_file.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("This is a sample file for the integrity checker.\nChange it after creating the baseline.\n")
        set_entry(self.i_file, path)
        self.set_status("Sample file created. Press 'Create baseline record', edit the file in Notepad, then 'Verify file'.")

    # ------------------------------------------------------------ 7. birthday attack
    def build_birthday(self, f):
        self.note(f, "Birthday paradox: a hash with n output bits has a collision after only about 2^(n/2) tries, not 2^n. "
                     "Here the hash is cut down to a few bits so you can actually watch a collision being found. "
                     "Real hashes (256 bits) are far too long for this, which is why their size matters.")
        row = ttk.Frame(f)
        row.pack(fill="x", pady=3)
        ttk.Label(row, text="Hash size in bits (8-36):", width=22).pack(side="left")
        self.b_bits = ttk.Spinbox(row, from_=8, to=36, width=6)
        self.b_bits.set(24)
        self.b_bits.pack(side="left", padx=6)
        ttk.Label(row, text="Algorithm:").pack(side="left", padx=(20, 0))
        self.b_algo = ttk.Combobox(row, values=hashing.ALGORITHMS, state="readonly", width=12)
        self.b_algo.set("sha256")
        self.b_algo.pack(side="left", padx=6)
        self.b_btn = self.buttons(f, [("Find a collision", self.b_run),
                                      ("Clear", lambda: self.clear(self.b_out))])[0]
        self.b_out = self.box(f, "Result", 16)

    def b_run(self):
        try:
            bits = int(self.b_bits.get())
        except ValueError:
            raise ValueError("Hash size must be a whole number between 8 and 36.")
        if not 8 <= bits <= 36:
            raise ValueError("Hash size must be between 8 and 36 bits.")
        algo = self.b_algo.get()

        def done(r):
            put(self.b_out,
                f"Hash size          : {r['bits']} bits ({algo.upper()}, truncated)\n\n"
                f"Message 1          : {r['message1']}\nMessage 2          : {r['message2']}\n"
                f"Both hash to       : {r['truncated_hash']}   (first {r['bits']} bits)\n\n"
                f"Tries needed       : {r['tries']:,}\n"
                f"Expected (~1.25 * 2^(n/2)) : {r['expected']:,}\n"
                f"Brute force would need     : up to {r['brute_force_needed']:,}\n\n"
                f"Two DIFFERENT messages with the SAME hash = a collision.\n"
                f"For a full 256-bit hash this needs about 2^128 tries, which is impossible.")
            self.set_status("Collision found.")

        self.run_async(lambda: hashing.birthday_attack(bits, algo), done, "Searching for a collision ...", self.b_btn)

    # ------------------------------------------------------------ 8. other ciphers
    HINTS = {
        "Caesar": "Key: a whole number shift, e.g. 3",
        "Vigenere": "Key: a word, e.g. LEMON",
        "Playfair": "Key: a word, e.g. MONARCHY (J is treated as I; decryption keeps filler X)",
        "Hill (2x2)": "Key: 4 letters (e.g. DDCF) or 4 numbers (e.g. 3 3 2 5); must be invertible mod 26",
        "Rail Fence": "Key: number of rails (at least 2), e.g. 3",
    }

    def build_other(self, f):
        self.note(f, "Extra classical ciphers from the same family: Caesar, Vigenere, Playfair, Hill and Rail Fence.")
        row = ttk.Frame(f)
        row.pack(fill="x", pady=3)
        ttk.Label(row, text="Cipher:", width=22).pack(side="left")
        self.oc_cipher = ttk.Combobox(row, values=list(self.HINTS), state="readonly", width=14)
        self.oc_cipher.current(0)
        self.oc_cipher.pack(side="left", padx=6)
        self.oc_hint = ttk.Label(row, text=self.HINTS["Caesar"], foreground="#555555")
        self.oc_hint.pack(side="left", padx=10)
        self.oc_cipher.bind("<<ComboboxSelected>>", lambda e: self.oc_hint.config(text=self.HINTS[self.oc_cipher.get()]))
        self.oc_key = self.entry(f, "Key:", 25, "3")
        self.oc_in = self.box(f, "Input text", 6)
        self.buttons(f, [("Encrypt", lambda: self.oc_apply(True)), ("Decrypt", lambda: self.oc_apply(False)),
                         ("Caesar: brute force", self.oc_brute), ("Caesar: frequency attack", self.oc_freq),
                         ("Show Playfair matrix", self.oc_matrix), ("Show rail fence", self.oc_rails),
                         ("Clear", lambda: self.clear(self.oc_in, self.oc_out, focus=self.oc_in))])
        self.oc_out = self.box(f, "Output", 8)

    def _int(self, text, what):
        try:
            return int(text.strip())
        except ValueError:
            raise ValueError(f"{what} must be a whole number.")

    def oc_apply(self, encrypt):
        name, key, text = self.oc_cipher.get(), self.oc_key.get(), get(self.oc_in)
        if name == "Caesar":
            fn = ciphers.caesar_encrypt if encrypt else ciphers.caesar_decrypt
            result = fn(text, self._int(key, "Shift"))
        elif name == "Vigenere":
            fn = ciphers.vigenere_encrypt if encrypt else ciphers.vigenere_decrypt
            result = fn(text, key)
        elif name == "Playfair":
            fn = ciphers.playfair_encrypt if encrypt else ciphers.playfair_decrypt
            result = fn(text, key)
        elif name == "Hill (2x2)":
            fn = ciphers.hill_encrypt if encrypt else ciphers.hill_decrypt
            result = fn(text, key)
        else:
            fn = ciphers.railfence_encrypt if encrypt else ciphers.railfence_decrypt
            result = fn(text, self._int(key, "Number of rails"))
        put(self.oc_out, result)
        self.set_status("Encrypted." if encrypt else "Decrypted.")

    def oc_brute(self):
        text = get(self.oc_in)
        if not any(c.isalpha() for c in text):
            raise ValueError("Paste a Caesar ciphertext in the input box.")
        put(self.oc_out, "\n".join(f"shift {s:2d}: {t}" for s, t in ciphers.caesar_bruteforce(text)))
        self.set_status("All 26 shifts tried - pick the line that reads as English.")

    def oc_freq(self):
        shift, text = ciphers.caesar_frequency_attack(get(self.oc_in))
        put(self.oc_out, f"Most likely shift: {shift}\n\n{text}")
        self.set_status("Shift guessed from letter frequencies (works best on longer text).")

    def oc_matrix(self):
        put(self.oc_out, ciphers.playfair_matrix_text(self.oc_key.get()))
        self.set_status("Playfair 5x5 matrix for this key (I and J share a cell).")

    def oc_rails(self):
        put(self.oc_out, ciphers.railfence_grid(get(self.oc_in), self._int(self.oc_key.get(), "Number of rails")))
        self.set_status("Zig-zag pattern: read row by row to get the ciphertext.")


if __name__ == "__main__":
    App().mainloop()