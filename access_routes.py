
"""Routes for accessing health records shared with the current user."""

import io
import json
import secrets
import sqlite3
from datetime import datetime
from zoneinfo import ZoneInfo

import db

from flask import (
    Blueprint,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from crypto_core import InvalidEnvelopeError
from share_access import (
    expire_old_requests,
    open_shared_item,
    revoke_request,
)
from share_errors import (
    InvalidKeyPackageError,
    KeyLockedError,
    KeyUnlockError,
    ShareAccessError,
)
from web_utils import current_user_id, require_csrf


access_bp = Blueprint("access", __name__)

ACCESS_ERROR_MESSAGE = "Akses tidak tersedia atau sudah berakhir."
PACKAGE_ERROR_MESSAGE = "Paket kunci atau password tidak dapat diverifikasi."
LOCKED_ERROR_MESSAGE = "Terlalu banyak percobaan. Coba lagi dalam 15 menit."
SERVER_ERROR_MESSAGE = "Data tidak dapat dibuka. Coba lagi nanti."
REVOKE_ERROR_MESSAGE = "Akses tidak dapat dicabut atau sudah tidak tersedia."
REVOKE_SERVER_ERROR_MESSAGE = "Akses gagal dicabut. Coba lagi nanti."

INLINE_MIME_TYPES = {
    "image/jpeg",
    "image/png",
    "application/pdf",
}

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


def _no_store(response):
    """Prevent shared health data from being cached."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@access_bp.route("/shared", methods=["GET"])
def shared_with_me():
    """Show active health records shared with the current user."""
    requester_id = current_user_id()

    if requester_id is None:
        return redirect(url_for("login"))

    csrf_token = session.get("csrf_token")

    if not csrf_token:
        csrf_token = secrets.token_hex(32)
        session["csrf_token"] = csrf_token

    try:
        expire_old_requests()

        now = datetime.now(
            ZoneInfo("Asia/Jakarta")
        ).strftime("%Y-%m-%d %H:%M:%S")

        connection = db.get_connection()

        try:
            rows = connection.execute(
                """
                SELECT
                    sr.id,
                    sr.owner_id,
                    u.username AS owner_username,
                    sr.category,
                    sr.created_at,
                    sr.expires_at,
                    si.id AS item_id,
                    si.category AS item_category,
                    si.created_at AS item_created_at
                FROM share_requests AS sr
                JOIN users AS u
                    ON u.id = sr.owner_id
                JOIN shared_items AS si
                    ON si.request_id = sr.id
                WHERE sr.requester_id = ?
                    AND sr.status = 'approved'
                    AND sr.expires_at > ?
                ORDER BY sr.expires_at ASC,
                    si.created_at ASC
                """,
                (requester_id, now),
            ).fetchall()
        finally:
            connection.close()

        shared_requests = {}

        for row in rows:
            request_id = row["id"]

            if request_id not in shared_requests:
                shared_requests[request_id] = {
                    "id": request_id,
                    "owner_id": row["owner_id"],
                    "owner_username": row["owner_username"],
                    "category": row["category"],
                    "created_at": row["created_at"],
                    "expires_at": row["expires_at"],
                    "items": [],
                }

            shared_requests[request_id]["items"].append({
                "id": row["item_id"],
                "category": row["item_category"],
                "created_at": row["item_created_at"],
            })

        response = make_response(
            render_template(
                "shared_view.html",
                shared_requests=list(shared_requests.values()),
                csrf_token=csrf_token,
            )
        )

        return _no_store(response)

    except (sqlite3.Error, OSError):
        return _no_store(
            make_response(
                "Data yang dibagikan tidak dapat dimuat. Coba lagi nanti.",
                503,
            )
        )


@access_bp.route(
    "/requests/<request_id>/revoke",
    methods=["POST"],
)
def revoke_shared(request_id):
    """Revoke an approved sharing request owned by the current user."""
    owner_id = current_user_id()

    if owner_id is None:
        return redirect(url_for("login"))

    require_csrf()

    try:
        revoke_request(
            owner_id=owner_id,
            request_id=request_id,
        )

        return _no_store(redirect("/requests"))

    except ShareAccessError:
        return _no_store(
            make_response(REVOKE_ERROR_MESSAGE, 404)
        )

    except (sqlite3.Error, OSError):
        return _no_store(
            make_response(REVOKE_SERVER_ERROR_MESSAGE, 503)
        )


@access_bp.route(
    "/shared/<request_id>/items/<item_id>",
    methods=["POST"],
)
def open_shared(request_id, item_id):
    """Open or download one item shared with the current user."""
    requester_id = current_user_id()

    if requester_id is None:
        return redirect(url_for("login"))

    require_csrf()

    package_text = request.form.get("package", "")
    password = request.form.get("password", "")
    mode = request.form.get("mode", "download")

    if mode not in {"view", "download"}:
        return _no_store(make_response("Mode tidak valid.", 400))

    if not package_text or not password:
        return _no_store(
            make_response(
                "Key package dan password wajib diisi.",
                400,
            )
        )

    try:
        metadata, file_bytes = open_shared_item(
            requester_id=requester_id,
            request_id=request_id,
            item_id=item_id,
            package_text=package_text,
            password=password,
        )

    except KeyLockedError:
        return _no_store(
            make_response(LOCKED_ERROR_MESSAGE, 429)
        )

    except (
        KeyUnlockError,
        InvalidKeyPackageError,
        InvalidEnvelopeError,
    ):
        return _no_store(
            make_response(PACKAGE_ERROR_MESSAGE, 400)
        )

    except ShareAccessError:
        return _no_store(
            make_response(ACCESS_ERROR_MESSAGE, 404)
        )

    except (sqlite3.Error, OSError):
        return _no_store(
            make_response(SERVER_ERROR_MESSAGE, 503)
        )

    mime_type = metadata["mime"]
    filename = metadata["filename"]

    # Display shared profile data as a table instead of a JSON download.
    if filename == "profil.json" and mime_type == "application/json":
        try:
            profile_data = json.loads(file_bytes.decode("utf-8"))

            if not isinstance(profile_data, dict):
                raise ValueError("Invalid profile data")

            profile_fields = [
                {
                    "label": label,
                    "value": profile_data.get(key),
                }
                for key, label in PROFILE_FIELDS
                if key in profile_data
            ]

        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            return _no_store(
                make_response(SERVER_ERROR_MESSAGE, 503)
            )

        csrf_token = session.get("csrf_token", "")

        response = make_response(
            render_template(
                "shared_profile.html",
                profile_fields=profile_fields,
                csrf_token=csrf_token,
            )
        )

        return _no_store(response)

    # Only explicitly allowed types may be displayed inline.
    inline = mode == "view" and mime_type in INLINE_MIME_TYPES

    response = send_file(
        io.BytesIO(file_bytes),
        mimetype=mime_type,
        as_attachment=not inline,
        download_name=filename,
    )

    return _no_store(response)
