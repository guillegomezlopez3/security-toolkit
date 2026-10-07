"""Password strength estimation and secure generation."""
import math
import secrets
import string

COMMON = {"password", "123456", "123456789", "qwerty", "abc123", "letmein", "admin", "welcome",
          "iloveyou", "monkey", "dragon", "football", "password1", "12345678", "contraseña"}
SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm", "0123456789"]


def charset_size(pw: str) -> int:
    size = 0
    if any(c.islower() for c in pw): size += 26
    if any(c.isupper() for c in pw): size += 26
    if any(c.isdigit() for c in pw): size += 10
    if any(c in string.punctuation for c in pw): size += len(string.punctuation)
    if any(ord(c) > 127 for c in pw): size += 32
    return size


def entropy_bits(pw: str) -> float:
    """Naive upper bound: length * log2(charset)."""
    size = charset_size(pw)
    return len(pw) * math.log2(size) if size else 0.0


def has_sequence(pw: str, run: int = 4) -> bool:
    low = pw.lower()
    for seq in SEQUENCES:
        for i in range(len(seq) - run + 1):
            chunk = seq[i:i + run]
            if chunk in low or chunk[::-1] in low:
                return True
    return False


def has_repeats(pw: str, run: int = 3) -> bool:
    return any(len(set(pw[i:i + run])) == 1 for i in range(len(pw) - run + 1))


def assess(pw: str) -> dict:
    """Return score (0-4), label, entropy and a list of human readable issues."""
    issues = []
    bits = entropy_bits(pw)
    if len(pw) < 10: issues.append("shorter than 10 characters")
    if pw.lower() in COMMON: issues.append("is a very common password")
    if has_sequence(pw): issues.append("contains a keyboard or alphabet sequence")
    if has_repeats(pw): issues.append("repeats the same character 3+ times")
    if charset_size(pw) < 62: issues.append("mixes fewer than 3 character types")
    if pw.lower() in COMMON or not pw:
        score = 0
    else:
        score = 0 if bits < 28 else 1 if bits < 40 else 2 if bits < 60 else 3 if bits < 80 else 4
        score = max(0, score - (1 if has_sequence(pw) or has_repeats(pw) else 0))
    label = ["very weak", "weak", "fair", "strong", "very strong"][score]
    return {"score": score, "label": label, "entropy_bits": round(bits, 1), "issues": issues}


def generate(length: int = 16, symbols: bool = True) -> str:
    """Cryptographically secure random password containing every selected character class."""
    if length < 8:
        raise ValueError("length must be at least 8")
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        pools.append("!@#$%^&*()-_=+[]{}")
    chars = [secrets.choice(p) for p in pools]
    alphabet = "".join(pools)
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)
