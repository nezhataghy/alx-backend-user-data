#!/usr/bin/env python3
""" Module of auth
"""
import os

from typing import List
from typing import TypeVar


class Auth:
    """Auth class."""

    AUTH_KEY: str = ""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Method that require authentication.
        :param path:
        :param excluded_paths:
        :return:
        """
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True

        if path[-1] != '/':
            path += '/'

        for p in excluded_paths:
            if p == path:
                return False
            if p[-1] == '*' and path.startswith(p[:-1]):
                return False

        if path in excluded_paths:
            return False
        return True

    def authorization_header(self, request=None) -> str:
        """
        Method that require authorization header.
        :param request:
        :return:
        """
        if request is None or request.headers.get('Authorization') is None:
            return None
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Method that require current user.
        :param request:
        :return:
        """
        return None

    def session_cookie(self, request=None):
        """
        Method that require session cookie.
        :param request:
        :return:
        """
        if request is None:
            return None

        session_name = os.getenv('SESSION_NAME')
        return request.cookies.get(session_name)
