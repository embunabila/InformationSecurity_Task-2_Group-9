"""Routes for managing health record sharing requests."""

import secrets
import sqlite3

from flask import (
    Blueprint,
    current_app,
    flash,
    get_flashed_messages,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from crypto_core import InvalidEnvelopeError

from db import (
    get_medical_files_for_owner,
    get_user_by_id,
)
from share_errors import ShareAccessError
from share_requests import (
    approve_request,
    create_request,
    get_incoming_requests,
    get_outgoing_requests,
    get_request_for_owner,
    reject_request,
)
from user_keys import get_public_key
from web_utils import current_user_id, require_csrf


requests_bp = Blueprint("requests", __name__)

SERVER_ERROR_MESSAGE = (
    "Your requests could not be accessed. Please try again later."
)

ACCESS_ERROR_MESSAGE = "Akses tidak tersedia atau sudah berakhir."
SEND_ERROR_MESSAGE = (
    "The request could not be sent. Check the username and try again."
)
APPROVE_ERROR_MESSAGE = (
    "The request could not be approved. Check your selection and try again."
)

SAFE_SEND_ERRORS = {
    "Owner username cannot be empty.",
    "Invalid sharing category.",
    "Reason cannot be empty.",
    "Reason cannot exceed 500 characters.",
    "You need to generate a keypair before requesting data.",
}

SUCCESS = "requests-success"
ERROR = "requests-error"

PROFILE_FIELDS = (
    ("name", "Name"),
    ("birth_date", "Birth date"),
    ("gender", "Gender"),
    ("weight", "Weight"),
    ("height", "Height"),
    ("phone", "Phone"),
    ("emergency_contact", "Emergency contact"),
    ("allergies", "Allergies"),
    ("health_conditions", "Health conditions"),
    ("routine_medication", "Routine medication"),
)


@requests_bp.after_request
def _prevent_request_page_caching(response):
    """Prevent private request information from being cached."""
    response.headers["Cache-Control"] = "no-store"
    return response


def _ensure_csrf_token():
    """Ensure a CSRF token is available for request forms."""
    token = session.get("csrf_token")

    if not isinstance(token, str) or not token:
        token = secrets.token_hex(32)
        session["csrf_token"] = token

    return token


def _server_error():
    """Return a generic response without exposing internal details."""
    return make_response(SERVER_ERROR_MESSAGE, 503)


def _load_page_data(user_id):
    """Load all data required by requests.html."""
    incoming = get_incoming_requests(user_id)
    outgoing = get_outgoing_requests(user_id)

    files = get_medical_files_for_owner(user_id)

    owner_files = {
        "identity": [],
        "document": [],
        "video": [],
    }

    for file in files:
        category = file["category"]

        if category in owner_files:
            owner_files[category].append(file)

    return {
        "has_keypair": get_public_key(user_id) is not None,
        "incoming": incoming,
        "outgoing": outgoing,
        "owner_files": owner_files,
        "profile_fields": PROFILE_FIELDS,
        "csrf_token": _ensure_csrf_token(),
    }


def _render_requests(user_id):
    """Render the requests page with any message from the last action."""
    page_data = _load_page_data(user_id)

    notices = get_flashed_messages(category_filter=[SUCCESS])
    errors = get_flashed_messages(category_filter=[ERROR])

    return render_template(
        "requests.html",
        **page_data,
        notice=notices[-1] if notices else None,
        error=errors[-1] if errors else None,
    )


def _back_to_requests(message, category):
    """Store a message and redirect, so a page refresh does not resend the form."""
    flash(message, category)
    return redirect(url_for("requests.my_requests"))


def _authenticated_user():
    """Return the authenticated user or None."""
    user_id = current_user_id()

    if user_id is None:
        return None

    user = get_user_by_id(user_id)

    if user is None:
        session.clear()
        return None

    return user_id


@requests_bp.route("/requests", methods=["GET"])
def my_requests():
    """Display incoming and outgoing sharing requests."""
    try:
        user_id = _authenticated_user()

        if user_id is None:
            return redirect(url_for("login"))

        return _render_requests(user_id)

    except sqlite3.Error:
        return _server_error()


@requests_bp.route("/requests", methods=["POST"])
def send_request():
    """Create a new sharing request."""
    user_id = _authenticated_user()

    if user_id is None:
        return redirect(url_for("login"))

    require_csrf()

    try:
        owner_username = request.form.get("owner_username", "")
        category = request.form.get("category", "")
        reason = request.form.get("reason", "")

        create_request(
            requester_id=user_id,
            owner_username=owner_username,
            category=category,
            reason=reason,
        )

        return _back_to_requests("Your sharing request has been sent.", SUCCESS)

    except ValueError as exc:
        message = str(exc) if str(exc) in SAFE_SEND_ERRORS else SEND_ERROR_MESSAGE
        return _back_to_requests(message, ERROR)

    except sqlite3.Error:
        return _server_error()


@requests_bp.route(
    "/requests/<request_id>/approve",
    methods=["POST"],
)
def approve_sharing_request(request_id):
    """Approve a pending request and share the selected data."""
    user_id = _authenticated_user()

    if user_id is None:
        return redirect(url_for("login"))

    require_csrf()

    try:
        request_row = get_request_for_owner(user_id, request_id)

        category = request_row["category"]

        if category == "profile":
            selection = {
                "profile_fields": request.form.getlist("profile_fields"),
            }
        else:
            selection = {
                "file_ids": request.form.getlist("file_ids"),
            }

        days_value = request.form.get("days", "")

        try:
            days = int(days_value)
        except (TypeError, ValueError):
            raise ValueError(
                "Expiry must be 1, 7, or 30 days."
            ) from None

        approve_request(
            owner_id=user_id,
            request_id=request_id,
            selection=selection,
            days=days,
            master_key=current_app.config["MASTER_KEY"],
        )

        return _back_to_requests("The sharing request has been approved.", SUCCESS)

    except ValueError:
        return _back_to_requests(APPROVE_ERROR_MESSAGE, ERROR)

    except ShareAccessError:
        return _back_to_requests(ACCESS_ERROR_MESSAGE, ERROR)

    except InvalidEnvelopeError:
        # The owner's original file failed its integrity check.
        return _back_to_requests(APPROVE_ERROR_MESSAGE, ERROR)

    except (sqlite3.Error, OSError):
        return _server_error()


@requests_bp.route(
    "/requests/<request_id>/reject",
    methods=["POST"],
)
def reject_sharing_request(request_id):
    """Reject a pending sharing request."""
    user_id = _authenticated_user()

    if user_id is None:
        return redirect(url_for("login"))

    require_csrf()

    try:
        reject_request(
            owner_id=user_id,
            request_id=request_id,
        )

        return _back_to_requests("The sharing request has been rejected.", SUCCESS)

    except ShareAccessError:
        return _back_to_requests(ACCESS_ERROR_MESSAGE, ERROR)

    except sqlite3.Error:
        return _server_error()