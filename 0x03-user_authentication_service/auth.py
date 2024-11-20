#!/usr/bin/env python3
"""
Auth module for handling authentication.
"""
import uuid
from uuid import uuid4
import bcrypt
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


def _generate_uuid() -> str:
    """
    Generate a new UUID and return its string representation.

    Returns:
        str: A string representation of a UUID.
    """
    return str(uuid.uuid4())


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

    def valid_login(self, email: str, password: str) -> bool:
        """
        Validate user login credentials.

        Args:
            email (str): User's email.
            password (str): User's password.

        Returns:
            bool: True if credentials are valid, False otherwise.
        """
        try:
            user = self._db.find_user_by(email=email)
            return bcrypt.checkpw(password.encode('utf-8'),
                                  user.hashed_password.encode('utf-8'))
        except NoResultFound:
            return False

    def create_session(self, email: str) -> Optional[str]:
        """
        Create a session for a user identified by email.

        Args:
            email (str): The user's email.

        Returns:
            Optional[str]: The session ID, or None if the user is not found.
        """
        try:
            # Find the user by email
            user = self._db.find_user_by(email=email)

            # Generate a new UUID for the session
            session_id = _generate_uuid()

            # Update the user's session_id in the database
            self._db.update_user(user.id, session_id=session_id)

            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str):
        """
        Return the User object associated with a given session_id.
        If session_id is None or no user is found, return None.
        """
        if not session_id:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """
        Updates the user's session_id to None.
        Args:
            user_id (int): The ID of the user
            whose session is to be destroyed.
        Returns:
            None
        """
        try:
            user = self._db.find_user_by(id=user_id)
            self._db.update_user(user.id, session_id=None)
        except NoResultFound:
            pass

    def get_reset_password_token(self, email: str) -> str:
        """
        Generates a reset password token
        for the user with the given email.
        - If the user does not exist, raises a ValueError.
        - Otherwise, generates a UUID and updates the user's reset_token.
        Returns the reset token as a string.
        """
        user = self._db.find_user_by(email=email)
        if not user:
            raise ValueError(f"User with email {email} does not exist")

        reset_token = str(uuid.uuid4())
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """
        Update the user's password using the reset token.

        Args:
            reset_token (str): The reset token provided for the user.
            password (str): The new password to set.

        Raises:
            ValueError: If the reset_token is invalid or does not exist.
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError("Invalid reset token.")

        hashed_password = bcrypt.hashpw(
            password.encode('utf-8'), bcrypt.gensalt())
        self._db.update_user(
            user.id, hashed_password=hashed_password, reset_token=None)
