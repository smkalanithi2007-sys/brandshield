import os
from datetime import datetime, timedelta, timezone

import jwt
from pwdlib import PasswordHash

password_hash = PasswordHash.recommended()
TOKEN_LIFETIME = timedelta(hours=12)


def secret_key() -> str:
    secret = os.getenv("JWT_SECRET_KEY", "")
    if len(secret) < 32:
        raise RuntimeError(
            "Set JWT_SECRET_KEY to a randomly generated value of at least "
            "32 characters."
        )
    return secret


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    return password_hash.verify(password, stored_hash)


def create_access_token(user_id: int) -> str:
    issued_at = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": str(user_id),
            "iat": issued_at,
            "exp": issued_at + TOKEN_LIFETIME,
        },
        secret_key(),
        algorithm="HS256",
    )


def decode_access_token(token: str) -> int | None:
    try:
        payload = jwt.decode(
            token, secret_key(), algorithms=["HS256"], options={"require": ["sub", "exp"]}
        )
        return int(payload["sub"])
    except (jwt.PyJWTError, TypeError, ValueError):
        return None
