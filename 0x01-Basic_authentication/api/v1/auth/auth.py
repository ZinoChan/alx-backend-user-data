#!/usr/bin/env python3
"""
Auth class
"""
from flask import request
from typing import (
    List,
    TypeVar
)


class Auth:
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        does path requires authentication or not
        """
        if path is None:
            return True
        elif excluded_paths is None or not excluded_paths:
            return True
        elif any(path.startswith(prefix.rstrip('*')) for prefix in excluded_paths):
            return False
        else:
            return True

    def authorization_header(self, request=None) -> str:
        """
        Returns none
        """
        if request is None:
            return None
        header = request.headers.get('Authorization')
        if header is None:
            return None
        return header

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Returns none
        """
        return None
