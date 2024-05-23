#!/usr/bin/env python3
"""
Module of auth
SessionExpAuth class.
"""
import os
from datetime import datetime, timedelta
from api.v1.auth.session_auth import SessionAuth


class SessionExpAuth(SessionAuth):
    """
    SessionExpAuth class.
    """
    def __init__(self):
        """
        Constructor.
        Set the session duration.
        Session duration is set to 0 if SESSION_DURATION is not set.
        """
        self.session_duration = int(os.getenv('SESSION_DURATION', 0))

    def create_session(self, user_id: str = None) -> str:
        """
        Create a session.
        :param user_id:
        :return:
        """
        session_id = super().create_session(user_id)
        if session_id is None:
            return None
        session_dictionary = {'user_id': user_id, 'created_at': datetime.now()}
        self.user_id_by_session_id[session_id] = session_dictionary
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Return the User ID by requesting it.
        :param session_id:
        :return:
        """
        if session_id is None or not isinstance(session_id, str):
            return None
        session_dictionary = self.user_id_by_session_id.get(session_id)
        if session_dictionary is None:
            return None
        user_id = session_dictionary.get('user_id')
        if user_id is None:
            return None
        if self.session_duration <= 0:
            return user_id
        created_at = session_dictionary.get('created_at')
        if created_at is None:
            return None
        allowed_window = created_at + timedelta(seconds=self.session_duration)
        if allowed_window < datetime.now():
            return None
        return user_id
