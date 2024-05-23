#!/usr/bin/env python3
"""
Module of auth
SessionAuth class.
"""
import uuid
from typing import TypeVar
from api.v1.auth.auth import Auth
from models.user import User


class SessionAuth(Auth):
    """Auth class."""

    AUTH_KEY: str = ""
    user_id_by_session_id: dict = {}

    def create_session(self, user_id: str = None) -> str:
        """
        Create a session.
        :param user_id:
        :return:
        """
        if user_id is None or not isinstance(user_id, str):
            return None
        session_id = str(uuid.uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Return the User ID by requesting it.
        :param session_id:
        :return:
        """
        if session_id is None or not isinstance(session_id, str):
            return None
        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Method that require current user.
        :param request:
        :return:
        """
        session_id = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_id)

        return User.get(user_id)

    def destroy_session(self, request=None):
        """
        Destroy a session.
        :param request:
        :return:
        """
        if request is None:
            return False
        session_id = self.session_cookie(request)
        if session_id is None:
            return False
        user_id = self.user_id_for_session_id(session_id)
        if user_id is None:
            return False
        del self.user_id_by_session_id[session_id]
        return True
