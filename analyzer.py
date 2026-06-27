"""
Core password strength analysis logic.
Shared by the CLI front-end (cli.py).
"""

import re
import math
from common_passwords import COMMON_PASSWORDS

KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]

SEQUENTIAL_ALPHA = "abcdefghijklmnopqrstuvwxyz"
SEQUENTIAL_NUM = "0123456789"


def _has_keyboard_pattern(password: str, min_run: int = 4) -> bool:
    """Detect substrings that walk along a keyboard row, e.g. 'qwerty', 'asdf'."""
    pw = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - min_run + 1):
            chunk = row[i:i + min_run]
            if chunk in pw or chunk[::-1] in pw:
                return True
    return False


def _has_sequential_chars(password: str, min_run: int = 4) -> bool:
    """Detect ascending/descending runs like 'abcd' or '4321'."""
    pw = password.lower()
    for seq in (SEQUENTIAL_ALPHA, SEQUENTIAL_NUM):
        for i in range(len(seq) - min_run + 1):
            chunk = seq[i:i + min_run]
            if chunk in pw or chunk[::-1] in pw:
                return True
    return False


def _has_repeated_chars(password: str, min_run: int = 3) -> bool:
    """Detect a single character repeated min_run+ times in a row, e.g. 'aaaa'."""
    return re.search(r"(.)\1{" + str(min_run - 1) + ",}", password) is not None


def _char_classes(password: str) -> dict:
    return {
        "lower": bool(re.search(r"[a-z]", password)),
        "upper": bool(re.search(r"[A-Z]", password)),
        "digit": bool(re.search(r"\d", password)),
        "symbol": bool(re.search(r"[^a-zA-Z0-9]", password)),
    }


def _pool_size(classes: dict) -> int:
    size = 0
    if classes["lower"]:
        size += 26
    if classes["upper"]:
        size += 26
    if classes["digit"]:
        size += 10
    if classes["symbol"]:
        size += 32
    return size or 1


def estimate_entropy_bits(password: str) -> float:
    """Rough entropy estimate: log2(pool_size) * length."""
    classes = _char_classes(password)
    pool = _pool_size(classes)
    if not password:
        return 0.0
    return len(password) * math.log2(pool)


def crack_time_estimate(entropy_bits: float) -> str:
    """
    Very rough offline crack-time estimate assuming 10 billion guesses/sec
    (a fast offline GPU attack against an unsalted/weakly-hashed password).
    This is illustrative, not a precise security guarantee.
    """
    guesses = 2 ** entropy_bits
    seconds = guesses / 1e10

    periods = [
        ("seconds", 60),
        ("minutes", 60),
        ("hours", 24),
        ("days", 365),
        ("years", 100),
        ("centuries", float("inf")),
    ]
    value = seconds
    unit = "seconds"
    for name, size in periods:
        unit = name
        if value < size:
            break
        value /= size

    if seconds < 1:
        return "instantly"
    return f"~{value:,.1f} {unit}"


def analyze_password(password: str) -> dict:
    """
    Analyze a password and return a dict with:
      - score: 0-4 (Very Weak .. Very Strong)
      - label: human readable label
      - entropy_bits: estimated entropy
      - crack_time: rough offline crack-time estimate
      - issues: list of problems found
      - suggestions: list of actionable improvements
      - is_common: whether it's in the common-password list
    """
    issues = []
    suggestions = []

    pw = password
    length = len(pw)
    classes = _char_classes(pw)
    is_common = pw.lower() in COMMON_PASSWORDS

    # --- Length checks ---
    if length == 0:
        return {
            "score": 0,
            "label": "Empty",
            "entropy_bits": 0.0,
            "crack_time": "instantly",
            "issues": ["Password is empty."],
            "suggestions": ["Enter a password to analyze."],
            "is_common": False,
        }

    if length < 8:
        issues.append("Too short (under 8 characters).")
        suggestions.append("Use at least 12 characters — longer is always stronger.")
    elif length < 12:
        issues.append("Below the recommended minimum of 12 characters.")
        suggestions.append("Aim for 12+ characters; consider a passphrase of 4-5 random words.")

    # --- Complexity checks ---
    missing = [name for name, present in classes.items() if not present]
    class_count = sum(classes.values())
    if class_count <= 1:
        issues.append("Uses only one type of character (e.g. only lowercase letters).")
    elif class_count < 3:
        issues.append("Limited character variety.")

    if not classes["upper"]:
        suggestions.append("Add at least one uppercase letter.")
    if not classes["lower"]:
        suggestions.append("Add at least one lowercase letter.")
    if not classes["digit"]:
        suggestions.append("Add at least one number.")
    if not classes["symbol"]:
        suggestions.append("Add at least one symbol (e.g. ! @ # $ %).")

    # --- Pattern checks ---
    if _has_keyboard_pattern(pw):
        issues.append("Contains a keyboard walk pattern (e.g. 'qwerty', 'asdf').")
        suggestions.append("Avoid adjacent keyboard keys typed in sequence.")

    if _has_sequential_chars(pw):
        issues.append("Contains a sequential run (e.g. 'abcd', '1234').")
        suggestions.append("Avoid simple ascending/descending sequences.")

    if _has_repeated_chars(pw):
        issues.append("Contains a repeated character run (e.g. 'aaaa').")
        suggestions.append("Avoid repeating the same character multiple times in a row.")

    # --- Common password check ---
    if is_common:
        issues.append("This is one of the most commonly used passwords — it would be guessed instantly.")
        suggestions.append("Never reuse common passwords. Use a unique, randomly generated password or passphrase.")

    # --- Scoring ---
    entropy_bits = estimate_entropy_bits(pw)

    score = 0
    if not is_common:
        if length >= 8:
            score += 1
        if length >= 12:
            score += 1
        if class_count >= 3:
            score += 1
        if class_count == 4:
            score += 1
        if entropy_bits >= 60 and not (_has_keyboard_pattern(pw) or _has_sequential_chars(pw) or _has_repeated_chars(pw)):
            score += 1

    # Cap and penalize patterns
    if _has_keyboard_pattern(pw) or _has_sequential_chars(pw) or _has_repeated_chars(pw):
        score = max(0, score - 1)

    score = max(0, min(4, score))
    if is_common:
        score = 0  # common passwords are always "Very Weak" regardless of shape

    labels = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
    label = labels[score]

    if not suggestions and score < 4:
        suggestions.append("Consider lengthening the password or adding more variety for extra margin.")

    if not issues:
        issues.append("No major issues detected.")

    return {
        "score": score,
        "label": label,
        "entropy_bits": round(entropy_bits, 1),
        "crack_time": crack_time_estimate(entropy_bits) if not is_common else "instantly",
        "issues": issues,
        "suggestions": suggestions,
        "is_common": is_common,
    }
