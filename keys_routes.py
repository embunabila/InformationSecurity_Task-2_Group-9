"""Routes for managing the current user's RSA keypair."""

import secrets
import sqlite3

from flask import (
    Blueprint,
    flash,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from db import get_user_by_id
from share_errors import KeyUnlockError
from web_utils import current_user_id, require_csrf


keys_bp = Blueprint("keys", __name__)


VERIFICATION_ERROR_MESSAGE = (
    "Paket kunci atau password tidak dapat diverifikasi."
)

DUPLICATE_KEY_MESSAGE = (
    "You already have a keypair."
)

SERVER_ERROR_MESSAGE = (
    "Your keys could not be accessed. Please try again later."
)


@keys_bp.after_request
def _prevent_key_page_caching(response):
    """Prevent key management responses from being cached."""
    response.headers["Cache-Control"] = "no-store"
    return response


def _ensure_csrf_token() -> str:
    """Ensure a CSRF token is available for the page forms."""

    token = session.get("csrf_token")

    if not isinstance(token, str) or not token:
        token = secrets.token_hex(32)
        session["csrf_token"] = token

    return token


def _render_keys(keypair, error=None, status=200):
    """Render the key management page without sensitive data."""

    return (
        render_template(
            "keys.html",
            keypair=keypair,
            error=error,
            csrf_token=_ensure_csrf_token(),
        ),
        status,
    )


def _server_error():
    """Return a generic response without internal error details."""

    return make_response(
        SERVER_ERROR_MESSAGE,
        503,
    )


@keys_bp.route("/keys", methods=["GET"])
def my_keys():
    """Display the current user's keypair status."""

    from user_keys import get_public_key

    user_id = current_user_id()

    if user_id is None:
        return redirect(url_for("login"))

    try:
        user = get_user_by_id(user_id)

        if user is None:
            session.clear()
            return redirect(url_for("login"))

        keypair = get_public_key(user_id)

    except sqlite3.Error:
        return _server_error()

    return _render_keys(keypair)


@keys_bp.route("/keys/generate", methods=["POST"])
def generate_keys():
    """Generate a keypair for the authenticated user."""

    from user_keys import (
        generate_user_keypair,
        get_public_key,
    )

    user_id = current_user_id()

    if user_id is None:
        return redirect(url_for("login"))

    # Reject invalid CSRF tokens before any database or crypto operation.
    require_csrf()

    try:
        user = get_user_by_id(user_id)

        if user is None:
            session.clear()
            return redirect(url_for("login"))

        # Check whether the current user already has a keypair.
        keypair = get_public_key(user_id)

        if keypair is not None:
            return _render_keys(
                keypair,
                error=DUPLICATE_KEY_MESSAGE,
                status=409,
            )

        # Preserve the exact submitted password.
        password = request.form.get("password", "")

        if not password:
            return _render_keys(
                None,
                error=VERIFICATION_ERROR_MESSAGE,
                status=400,
            )

        # Reuse the existing cryptographic service.
        generate_user_keypair(
            user_id,
            password,
        )

    except KeyUnlockError:
        return _render_keys(
            None,
            error=VERIFICATION_ERROR_MESSAGE,
            status=400,
        )

    except ValueError:
        # A concurrent request may have generated a keypair
        # after the initial ownership check.
        try:
            keypair = get_public_key(user_id)

        except sqlite3.Error:
            return _server_error()

        if keypair is not None:
            return _render_keys(
                keypair,
                error=DUPLICATE_KEY_MESSAGE,
                status=409,
            )

        # Do not expose unexpected validation or crypto errors.
        return _server_error()

    except (sqlite3.Error, OSError, MemoryError):
        return _server_error()

    flash(
        "Your keypair has been generated successfully.",
        "keys-success",
    )

    return redirect(
        url_for("keys.my_keys"),
        code=303,
    )