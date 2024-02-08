#!/usr/bin/env python3
"""
Module for encrypting passwords
"""

import bcrypt


def hash_password(password):
    """
    One string argument name password and return a
    salted, hashed password, which is a byte string
    """
    salted = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salted)
    return hashed_password


def is_valid(hashed_password, password):
    """
    Check validity of password and
    return a boolean"""
    return bcrypt.checkpw(password.encode(), hashed_password)


"""
Module for encrypting passwords
"""


def hash_password(password: str) -> bytes:
    """
    Hashes the provided password using bcrypt
    and returns the new password
    """
    salted_password = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salted_password)
    return hashed_password


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validates whether the provided password matches the hashed password
    and returns a boolean
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
