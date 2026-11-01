"""Rule-based, offline password analysis.

Entropy is shown as a rough character-pool upper-bound estimate only. It is
not a prediction of real-world guess count for human-chosen passwords.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
import math
import re
import unicodedata
from typing import Iterable

COMMON_PASSWORDS = {
    "password", "password1", "password123", "123456", "123456789",
    "12345678", "1234567890", "12345", "qwerty", "qwerty123",
    "admin", "admin123", "letmein", "welcome", "iloveyou",
    "monkey", "dragon", "football", "abc123", "111111",
    "000000", "passw0rd", "p@ssw0rd", "india123", "india@123",
    "changeme", "secret", "sunshine", "princess", "trustno1",
}
LEET = str.maketrans({"0":"o", "1":"i", "3":"e", "4":"a", "@":"a",
                      "$":"s", "5":"s", "7":"t", "!":"i"})
KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm",
                 "1234567890", "poiuytrewq", "lkjhgfdsa", "mnbvcxz")
SEQUENCES = ("abcdefghijklmnopqrstuvwxyz", "0123456789",
             "qwertyuiop", "asdfghjkl", "zxcvbnm")

@dataclass
class AnalysisResult:
    score: int
    rating: str
    length: int
    entropy_bits: float
    estimated_pool_size: int
    character_types: dict
    findings: list[str]
    recommendations: list[str]
    flags: dict

    def to_dict(self):
        return asdict(self)

def _normalise(s: str) -> str:
    return unicodedata.normalize("NFKC", s).casefold()

def _has_sequence(s: str, minimum: int = 3) -> bool:
    x = _normalise(s)
    for seq in SEQUENCES:
        for i in range(len(seq) - minimum + 1):
            chunk = seq[i:i+minimum]
            if chunk in x or chunk[::-1] in x:
                return True
    # Any ascending/descending run of Unicode code points.
    run = 1
    for a, b in zip(x, x[1:]):
        run = run + 1 if ord(b) - ord(a) in (1, -1) else 1
        if run >= minimum:
            return True
    return False

def _keyboard_pattern(s: str) -> bool:
    x = _normalise(s)
    return any(row[i:i+3] in x for row in KEYBOARD_ROWS
               for i in range(len(row)-2))

def _date_pattern(s: str) -> bool:
    patterns = (
        r"(?:19|20)\d{2}", r"(?:0?[1-9]|1[0-2])[/.-](?:0?[1-9]|[12]\d|3[01])",
        r"(?:0?[1-9]|[12]\d|3[01])[/.-](?:0?[1-9]|1[0-2])",
        r"(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])",
    )
    return any(re.search(p, s) for p in patterns)

def _repeat_pattern(s: str) -> bool:
    if re.search(r"(.)\1{2,}", s, re.DOTALL):
        return True
    return len(s) >= 4 and len(set(s)) <= max(2, len(s)//4)

def _character_pool(s: str) -> int:
    pool = 0
    if any(c.islower() for c in s): pool += 26
    if any(c.isupper() for c in s): pool += 26
    if any(c.isdigit() for c in s): pool += 10
    if any(not c.isalnum() and not c.isspace() for c in s): pool += 33
    if any(c.isspace() for c in s): pool += 1
    # Unicode beyond ASCII: count unique non-ASCII symbols conservatively.
    non_ascii = {c for c in s if ord(c) > 127}
    pool += min(len(non_ascii), 100)
    return max(pool, 1)

def analyze_password(password: str, user_context: Iterable[str] | None = None) -> AnalysisResult:
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if not password:
        return AnalysisResult(0, "Very Weak", 0, 0.0, 1, {
            "lowercase": False, "uppercase": False, "digits": False,
            "symbols": False, "whitespace": False, "unicode": False
        }, ["Password is empty."], ["Use a unique password or a long passphrase."],
        {"common": False, "sequence": False, "keyboard": False,
         "repeated": False, "date": False, "context": False, "short": True})

    n = len(password)  # Unicode code points
    lower = any(c.islower() for c in password)
    upper = any(c.isupper() for c in password)
    digits = any(c.isdigit() for c in password)
    symbols = any(not c.isalnum() and not c.isspace() for c in password)
    spaces = any(c.isspace() for c in password)
    unicode_chars = any(ord(c) > 127 for c in password)
    types = {"lowercase": lower, "uppercase": upper, "digits": digits,
             "symbols": symbols, "whitespace": spaces, "unicode": unicode_chars}

    norm = _normalise(password)
    de_leeted = norm.translate(LEET)
    compact = re.sub(r"[^a-z0-9]", "", norm)
    common = norm in COMMON_PASSWORDS or compact in COMMON_PASSWORDS or de_leeted in COMMON_PASSWORDS
    sequence = _has_sequence(password)
    keyboard = _keyboard_pattern(password)
    repeated = _repeat_pattern(password)
    date = _date_pattern(password)
    context_hit = False
    for item in user_context or ():
        token = _normalise(str(item)).strip()
        if len(token) >= 3 and (token in norm or token.translate(LEET) in de_leeted):
            context_hit = True
            break
    short = n < 8

    pool = _character_pool(password)
    raw_entropy = n * math.log2(pool)
    # Conservative heuristic deductions; this is explicitly not true entropy.
    deductions = 0
    findings, recs = [], []
    if short:
        findings.append("Very short password (under 8 characters).")
        recs.append("Use at least 15 characters for a single-factor account; a long passphrase is easier to remember.")
        deductions += 35
    elif n < 12:
        findings.append("Shorter than the recommended 15-character single-factor baseline.")
        recs.append("Increase the length toward 15 characters or more.")
        deductions += 12
    elif n < 15:
        findings.append("Length is reasonable, but longer is generally better.")
        deductions += 4
    if common:
        findings.append("Matches a common password or a predictable leetspeak variation.")
        recs.append("Avoid common passwords and trivial substitutions; choose a completely different phrase.")
        deductions += 45
    if sequence:
        findings.append("Contains an ascending or descending sequence.")
        recs.append("Avoid sequences such as abc, 123, or reversed sequences.")
        deductions += 15
    if keyboard:
        findings.append("Contains a predictable keyboard pattern.")
        recs.append("Avoid adjacent keyboard patterns such as qwerty or asdf.")
        deductions += 12
    if repeated:
        findings.append("Contains excessive repeated characters or a very small character variety.")
        recs.append("Avoid repeated runs such as aaa or 111.")
        deductions += 12
    if date:
        findings.append("Contains a date-like pattern or year.")
        recs.append("Avoid birthdays, years, and recognizable date formats.")
        deductions += 10
    if context_hit:
        findings.append("Contains a supplied personal/context word.")
        recs.append("Do not include your name, username, organisation, service name, or other personal details.")
        deductions += 25
    if len(password.strip()) != n:
        findings.append("Contains leading or trailing whitespace, which can cause entry mistakes.")
        recs.append("Avoid accidental leading or trailing spaces; intentional spaces inside passphrases are fine.")
        deductions += 3
    if not findings:
        findings.append("No obvious common-password or simple-pattern issue was detected.")
    # Composition is descriptive only: it is not a mandatory strength rule.
    if sum((lower, upper, digits, symbols)) == 1 and n < 15:
        findings.append("Uses only one main character category; length and unpredictability matter more than forced character mixing.")
    score = max(0, min(100, round(min(raw_entropy, 100) - deductions)))
    if common or short:
        score = min(score, 24 if common else 34)
    if score < 20: rating = "Very Weak"
    elif score < 40: rating = "Weak"
    elif score < 60: rating = "Moderate"
    elif score < 80: rating = "Strong"
    else: rating = "Very Strong"
    if not recs:
        recs.append("Keep it unique for every account and store it in a reputable password manager.")
    if n < 64:
        recs.append("Consider a longer, randomly generated password or multi-word passphrase.")
    return AnalysisResult(score, rating, n, round(raw_entropy, 1), pool,
        types, findings, list(dict.fromkeys(recs)),
        {"common": common, "sequence": sequence, "keyboard": keyboard,
         "repeated": repeated, "date": date, "context": context_hit, "short": short})
