#!/usr/bin/env python3
"""
BasicAuth module for managing basic authentication.
"""

from api.v1.auth.auth import Auth

class BasicAuth(Auth):
    """
    BasicAuth class for handling basic authentication.
    """

    def extract_base64_authorization_header(self, authorization_header: str) -> str:
        """
        Extracts the Base64 part of the Authorization header for Basic Authentication.

        Args:
            authorization_header (str): The Authorization header.

        Returns:
            str: The Base64 encoded part of the Authorization header, or None if
                 conditions are not met.
        """
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith("Basic "):
            return None
        return authorization_header[len("Basic "):]

    def decode_base64_authorization_header(self, base64_authorization_header: str) -> str:
        """
        Decodes a Base64 string.

        Args:
            base64_authorization_header (str): The Base64 encoded string.

        Returns:
            str: The decoded Base64 string, or None if conditions are not met.
        """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            return base64_authorization_header.encode('utf-8').decode('base64')
        except Exception:
            return None
          
          
    def extract_user_credentials(self, decoded_base64_authorization_header: str) -> (str, str): # type: ignore
      """
      Extracts the user credentials from the decoded Base64 string.

      Args:
          decoded_base64_authorization_header (str): The decoded Base64 string:

      Returns:
          Tuple[str, str]: The user email and password, or None if conditions are not met.
      """
      if decoded_base64_authorization_header is None:
          return None, None
      if not isinstance(decoded_base64_authorization_header, str):
          return None, None
      if ':' not in decoded_base64_authorization_header:
          return None, None
      email, password = decoded_base64_authorization_header.split(':', 1)
      return email, password
    
    def user_object_from_credentials(self, user_email: str, user_pwd: str) -> TypeVar('User'): # type: ignore
        """
        Retrieves the user object based on the email and password.

        Args:
            user_email (str): The user email.
            user_pwd (str): The user password.

        Returns:
            User: None for now. Will be implemented later.
        """
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None
        
        users = User.search({'email': user_email}) # type: ignore
        if not users:
            return None
        
        user = users[0]
        if not user.is_valid_password(user_pwd):
            return None
        return user
      
    def current_user(self, request=None) -> TypeVar('User'): # type: ignore
        pass