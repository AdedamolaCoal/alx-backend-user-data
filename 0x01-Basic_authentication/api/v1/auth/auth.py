#!/usr/bin/env python3
"""
Auth module for managing API authentication.
"""

from flask import request
from typing import List, TypeVar


class Auth:
    """
    Auth class to serve as a template for all authentication systems.
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determines if authentication is required based on the path.

        Args:
            path (str): The path to check.
            excluded_paths (List[str]): Paths that are excluded from auth.

        Returns:
            bool: True if path requires authentication, False otherwise.
        """
        if path is None:
            return True
        if excluded_paths is None or excluded_paths == []:
            return True
        if not path.endswith('/'):
            path += '/'
        for excluded_path in excluded_paths:
            if path == excluded_path:
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """
        Retrieves the Authorization header from the request.

        Args:
            request (Flask request): The request object.

        Returns:
            str: Authorization header or None if not present.
        """
        if request is None or 'Authorization' not in request.headers:
            return None
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):  # type: ignore
        """
        Retrieves the current user based on the request.

        Args:
            request (Flask request): The request object.

        Returns:
            User: None for now. Will be implemented later.
        """
        return None
