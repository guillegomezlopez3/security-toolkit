"""Salted password hashing with PBKDF2-HMAC-SHA256 and file integrity checksums."""
import base64
import hashlib
import hmac
import secrets

ITERATIONS = 600_000


def hash_password(password: str, iterations: int = ITERATIONS) -> str:
    """Return 'pbkdf2_sha256$iterations$salt$hash' (salt and hash base64-encoded)."""
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return "$".join(["pbkdf2_sha256", str(iterations),
                     base64.b64encode(salt).decode(), base64.b64encode(dk).decode()])


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_b64, hash_b64 = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        salt, expected = base64.b64decode(salt_b64), base64.b64decode(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iters))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk, expected)  # constant-time comparison


def file_checksum(path: str, algo: str = "sha256", chunk: int = 1 << 20) -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        while block := f.read(chunk):
            h.update(block)
    return h.hexdigest()
