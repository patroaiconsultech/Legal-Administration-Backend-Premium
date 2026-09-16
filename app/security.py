import hashlib, hmac, secrets, base64
from datetime import datetime, timedelta
from .config import get_settings

settings = get_settings()

def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def random_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)

def otp_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"

def hmac_hex(value: str, purpose: str) -> str:
    key = settings.secret_key.encode()
    return hmac.new(key, f"{purpose}:{value}".encode(), hashlib.sha256).hexdigest()

def hash_otp(code: str) -> str:
    return hmac_hex(code, "otp")

def verify_otp(code: str, expected: str) -> bool:
    return hmac.compare_digest(hash_otp(code), expected)

def hash_password(password: str, salt: bytes | None = None, iterations: int = 260_000) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(dk).decode()}"

def verify_password(password: str, encoded: str | None) -> bool:
    if not encoded:
        return False
    try:
        alg, it_s, salt_s, dk_s = encoded.split("$", 3)
        if alg != "pbkdf2_sha256":
            return False
        iterations = int(it_s)
        salt = base64.urlsafe_b64decode(salt_s)
        expected = base64.urlsafe_b64decode(dk_s)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False

def utcnow():
    return datetime.utcnow()

def expires(minutes: int = 0, hours: int = 0, days: int = 0):
    return utcnow() + timedelta(minutes=minutes, hours=hours, days=days)
