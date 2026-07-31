from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

def valid_passcode(value: str) -> bool:
    return len(value) == 6 and value.isdigit()

def hash_passcode(value: str) -> str:
    if not valid_passcode(value):
        raise ValueError("Passcode must be exactly six digits")
    return hasher.hash(value)

def verify_passcode(encoded: str, value: str) -> bool:
    if not valid_passcode(value):
        return False
    try:
        return hasher.verify(encoded, value)
    except (VerifyMismatchError, InvalidHashError):
        return False
