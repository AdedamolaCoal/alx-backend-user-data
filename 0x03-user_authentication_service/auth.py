#!/usr/bin/env python3
"""
Auth module for handling authentication.
"""
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from typing import Optional
from bcrypt import hashpw, gensalt


def _hash_password(password: str) -> bytes:
    """
    Hashes a password with a salt using bcrypt.

    Args:
        password (str): The password to hash.

    Returns:
        bytes: A salted hash of the password.
    """
    return hashpw(password.encode('utf-8'), gensalt())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        Registers a new user with the given email and password.

        Args:
            email (str): The email of the new user.
            password (str): The password of the new user.

        Returns:
            User: The newly created user.

        Raises:
            ValueError: If a user with the same email already exists.
        """
        try:
            self._db.find_user_by(email=email)
            # If no exception, user already exists
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            # If user not found, create a new user
            hashed_password = _hash_password(password)
            user = self._db.add_user(
                email=email, hashed_password=hashed_password.decode('utf-8'))
            return user
