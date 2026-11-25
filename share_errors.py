"""Shared error classes for the data sharing feature."""


class KeyUnlockError(Exception):
    """Wrong password, or the private key could not be unlocked."""


class InvalidKeyPackageError(Exception):
    """The key package is malformed or not meant for this request or user."""


class ShareAccessError(Exception):
    """No access, or the request was rejected, revoked, or has expired."""


class KeyLockedError(Exception):
    """Too many failed password attempts; the private key is temporarily locked."""