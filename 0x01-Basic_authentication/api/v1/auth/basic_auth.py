#!/usr/bin/env python3
"""
BasicAuth module
"""
import base64
from api.v1.auth.auth import Auth
from typing import Tuple, TypeVar
from models.user import User


class BasicAuth(Auth):
    """
    BasicAuth class that inherits from Auth
    """

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """
        Extracts the Base64 part of the Authorization
        header for Basic Authentication
        Returns:
            The Base64 part of the Authorization header or None
        """
        if authorization_header is None or not isinstance(authorization_header,
                                                          str):
            return None
        if not authorization_header.startswith("Basic "):
            return None
        return authorization_header.split("Basic ")[1].strip()

    def decode_base64_authorization_header(self,
                                           base64_authorization_header: str
                                           ) -> str:
        """
        Decodes a Base64 string
        Returns:
            The decoded value as a UTF-8 string or None
        """
        header = base64_authorization_header
        if header is None or not isinstance(header, str):
            return None
        try:
            decoded = base64.b64decode(base64_authorization_header)
            decoded_string = decoded.decode('utf-8')
            return decoded_string
        except base64.binascii.Error:
            return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header: str) -> Tuple[str, str]:  # nopep8
        """
        Extracts user credentials from a decoded Base64
        Returns:
            A tuple containing the user email and password
            or none if the header is invalid
        """
        decoded = decoded_base64_authorization_header
        if decoded is None or not isinstance(decoded, str):
            return None, None
        if ':' not in decoded:
            return None, None
        email, password = decoded.split(':', 1)
        return email, password

    def user_object_from_credentials(self,
                                     user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """
        Retrieves a User instance based on email and password credentials
        Returns:
            The User instance and credentials if valid, None otherwise
        """
        if type(user_email) == str and type(user_pwd) == str:
            try:
                users = User.search({'email': user_email})
            except Exception:
                return None
            if len(users) <= 0:
                return None
            if users[0].is_valid_password(user_pwd):
                return users[0]
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves the User instance for a request
        Returns:
            The User instance if authenticated, None otherwise
        """
        header = self.authorization_header(request)
        base64_auth = self.extract_base64_authorization_header(header)
        decoded_header = self.decode_base64_authorization_header(base64_auth)
        email, password = self.extract_user_credentials(decoded_header)
        return self.user_object_from_credentials(email, password)

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header: str) -> Tuple[str, str]:  # nopep8
        """
        Extracts the user credentials from the decoded authorization header
        Returns:
            A tuple containing the email and password
        """
        if not decoded_base64_authorization_header or not isinstance(decoded_base64_authorization_header, str):  # nopep8
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None
        credentials = decoded_base64_authorization_header.split(':', 1)
        email = credentials[0]
        password = credentials[1]
        return email, password
