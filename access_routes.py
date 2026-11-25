
"""Routes for accessing health records shared with the current user."""

import io
import sqlite3

from flask import (
    Blueprint,
    make_response,
    redirect,
    request,
    send_file,
    url_for,
)

from crypto_core import InvalidEnvelopeError
from share_access import open_shared_item
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

INLINE_MIME_TYPES = {
    "image/jpeg",
    "image/png",
    "application/pdf",
}


def _no_store(response):
    """Prevent shared health data from being cached."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


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

    # Only explicitly allowed types may be displayed inline.
    inline = mode == "view" and mime_type in INLINE_MIME_TYPES

    response = send_file(
        io.BytesIO(file_bytes),
        mimetype=mime_type,
        as_attachment=not inline,
        download_name=filename,
    )

    return _no_store(response)
