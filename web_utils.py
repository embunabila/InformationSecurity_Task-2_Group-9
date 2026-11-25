"""Shared helpers for the data sharing routes (login and CSRF)."""

import hmac

from flask import abort, request, session


def current_user_id():
    """Return the logged-in user's id from the session, or None."""
    user_id = session.get("user_id")

    # bool is a subclass of int, so reject it explicitly.
    if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id <= 0:
        return None

    return user_id


def require_csrf():
    """Abort with 400 if the form's CSRF token does not match the session."""
    expected = session.get("csrf_token")
    submitted = request.form.get("csrf_token", "")

    if not isinstance(expected, str) or not expected:
        abort(400)

    # Constant-time comparison so response time does not leak the token.
    if not hmac.compare_digest(submitted.encode("utf-8"), expected.encode("utf-8")):
        abort(400)