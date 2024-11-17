#!/usr/bin/env python3
"""
BasicAuth module for managing basic authentication.
"""

import base64
from models.user import User
from typing import Tuple, Optional
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """
    BasicAuth class for handling basic authentication.
    """

    def extract_base64_authorization_header(
        self, authorization_header: str
    ) -> str:
        """
        Extracts the Base64 part of the
        Authorization header for Basic Authentication.

        Args:
            authorization_header (str): The Authorization header.

        Returns:
            str: The Base64 encoded part of
            the Authorization header, or None if
                 conditions are not met.
        """
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith("Basic "):
            return None
        return authorization_header[len("Basic "):]

    def decode_base64_authorization_header(
        self,
        base64_authorization_header: str
    ) -> str:
        """
        Decodes a Base64 encoded string.

        Args:
            base64_authorization_header (str):
            The Base64 encoded string.

        Returns:
            str: The decoded string, or None if decoding fails.
        """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            return base64.b64decode(
                base64_authorization_header
            ).decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(
        self, decoded_base64_authorization_header: str
    ) -> Tuple[str, str]:
        """
        Extracts user email and password
        from Base64 decoded authorization header.

        Args:
            decoded_base64_authorization_header:
            Decoded Base64 authorization header.

        Returns:
            Tuple[str, str]: User email and password,
            or (None, None) if extraction fails.
        """
        if decoded_base64_authorization_header is None:
            return None, None

        if not isinstance(decoded_base64_authorization_header, str):
            return None, None

        if ':' not in decoded_base64_authorization_header:
            return None, None

        user_email, user_pwd = decoded_base64_authorization_header.split(
            ':', 1)
        return user_email, user_pwd

    def user_object_from_credentials(
        self, user_email: str, user_pwd: str
    ) -> Optional[User]:
        """
        Returns the User instance based on
        the user's email and password.

        Args:
            user_email (str): The user's email.
            user_pwd (str): The user's password.

        Returns:
            User or None: The User instance if
            credentials match, otherwise None.
        """
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        # Search for users with the specified email
        users = User.search({"email": user_email})
        if not users:
            return None

        user = users[0]
        if user.is_valid_password(user_pwd):
            return user

        return None

    def current_user(self, request=None) -> Optional[User]:
        """
        Retrieves the User instance for a request.

        Args:
            request: The Flask request object.

        Returns:
            User or None: The User instance if authenticated, otherwise None.
        """
        auth_header = self.authorization_header(request)
        if not auth_header:
            return None

        base64_auth = self.extract_base64_authorization_header(auth_header)
        if not base64_auth:
            return None

        decoded_auth = self.decode_base64_authorization_header(base64_auth)
        if not decoded_auth:
            return None

        user_email, user_pwd = self.extract_user_credentials(decoded_auth)
        if not user_email or not user_pwd:
            return None

        user = self.user_object_from_credentials(user_email, user_pwd)
        return user

    def require_auth(
        self, path: str, excluded_paths: list
    ) -> bool:
        """
        Determines if a path requires authentication
        based on excluded paths.

        Args:
            path (str): The path to check.
            excluded_paths (list): A list of paths that
            are excluded from authentication.

        Returns:
        bool: True if the path requires
        authentication, False otherwise.
        """
        if path is None or not excluded_paths:
            return True

        # Normalize the path by ensuring it does not end with a trailing slash
        if path[-1] != '/':
            path += '/'

        for excluded_path in excluded_paths:
            # Normalize excluded path as well
            if excluded_path[-1] != '/':
                excluded_path += '/'

            # Check if excluded path ends with '*' (wildcard)
            if excluded_path.endswith('*'):
                # Check if path starts with the excluded path
                # prefix (excluding the '*')
                if path.startswith(excluded_path[:-1]):
                    return False
            else:
                # Check for exact match
                if path == excluded_path:
                    return False

        return True
