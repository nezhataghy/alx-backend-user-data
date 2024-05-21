#!/usr/bin/env python3
""" Module of auth
"""
import base64
from typing import TypeVar

from api.v1.auth.auth import Auth
from models.user import User


class BasicAuth(Auth):
    """ BasicAuth class.
    """
    AUTH_KEY = "Basic "

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """ Extract base64 authorization header
        """
        if isinstance(authorization_header, str) and \
                authorization_header.startswith(self.AUTH_KEY):
            return authorization_header[len(self.AUTH_KEY):]

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: str
    ) -> str:
        """ Decode base64 authorization header
        """
        if isinstance(base64_authorization_header, str):
            try:
                return base64.b64decode(
                    base64_authorization_header.encode('utf-8')) \
                    .decode('utf-8')
            except Exception:
                pass
        return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str
    ) -> (str, str):
        """ Extract user credentials
        """
        if isinstance(decoded_base64_authorization_header, str) and \
                ":" in decoded_base64_authorization_header:
            return tuple(decoded_base64_authorization_header.split(":", 1))
        return (None, None)

    def user_object_from_credentials(
            self,
            user_email: str,
            user_pwd: str
    ) -> Auth:
        """ User object from credentials
        """
        if not isinstance(user_email, str) and not isinstance(user_pwd, str):
            return None

        try:
            user = User.search({"email": user_email})
            if user:
                if user[0].is_valid_password(user_pwd):
                    return user[0]
            else:
                return None
        except Exception:
            return None
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ Method that require current user.
        """
        authorization_header = self.authorization_header(request)
        if not authorization_header:
            return None

        base64_authorization_header = \
            self.extract_base64_authorization_header(authorization_header)
        if not base64_authorization_header:
            return None

        decoded_base64_authorization_header = \
            self.decode_base64_authorization_header(
                base64_authorization_header)
        if not decoded_base64_authorization_header:
            return None

        user_credentials = self.extract_user_credentials(
            decoded_base64_authorization_header)
        if not user_credentials:
            return None

        user = self.user_object_from_credentials(
            user_credentials[0], user_credentials[1])
        return user
