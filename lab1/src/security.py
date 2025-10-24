"""Utilities for password hashing and verification."""

from __future__ import annotations

import hashlib
import hmac


def hash_password(password: str, salt: str) -> str:
    """Return deterministic SHA-256 hash for password with provided salt."""
    value = f"{salt}:{password}".encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    """Constant-time comparison for password check."""
    calculated = hash_password(password, salt)
    return hmac.compare_digest(calculated, expected_hash)
