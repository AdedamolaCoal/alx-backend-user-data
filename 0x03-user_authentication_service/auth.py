#!/usr/bin/env python3
"""
Auth module for handling authentication.
"""
import bcrypt


def _hash_password(password: str) -> bytes:
    """
    Hashes a password with a salt using bcrypt.

    Args:
        password (str): The password to hash.

    Returns:
        bytes: A salted hash of the password.
    """
    # Generate a salt
    salt = bcrypt.gensalt()
    # Hash the password with the salt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password
