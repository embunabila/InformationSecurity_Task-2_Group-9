"""Key package page: the owner copies or downloads the package to send."""

import io
import secrets
import sqlite3
import uuid

from flask import (
    Blueprint,
    make_response,
    redirect,
    render_template,
    send_file,
    session,
    url_for,
)

from db import get_user_by_id
from share_errors import ShareAccessError
from web_utils import current_user_id

grant_bp = Blueprint("grant", __name__)

ACCESS_ERROR_MESSAGE = "Akses tidak tersedia atau sudah berakhir."
PACKAGE_ERROR_MESSAGE = "Paket kunci tidak dapat dibuat. Coba lagi nanti."


class _PackageUnavailable(Exception):
    pass


def _is_lowercase_uuid(value):
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


def _load_package(owner_id, request_id):
    """Return the data the package page needs, or raise ShareAccessError."""
    # Imported here so the app still starts while these modules are missing
    # from main; app.py imports this file at startup.
    from share_access import expire_old_requests
    from share_keys import build_key_package
    from share_requests import get_request_for_owner
    from user_keys import get_public_key, public_key_fingerprint

    if not _is_lowercase_uuid(request_id):
        raise ShareAccessError("Unknown request id.")

    expire_old_requests()

    # Raises ShareAccessError unless owner_id owns this request.
    share_request = get_request_for_owner(owner_id, request_id)

    if share_request["status"] != "approved" or share_request["wrapped_key"] is None:
        raise ShareAccessError("Request is not approved.")

    requester_key = get_public_key(share_request["requester_id"])
    if requester_key is None:
        raise ShareAccessError("Requester has no key pair.")

    # Recompute from the PEM instead of trusting the stored column.
    fingerprint = public_key_fingerprint(requester_key["public_key_pem"])
    if fingerprint != requester_key["fingerprint"]:
        raise _PackageUnavailable("Stored fingerprint does not match the key.")

    try:
        package = build_key_package(
            request_id,
            bytes(share_request["wrapped_key"]),
            fingerprint,
        )
    except ValueError:
        raise _PackageUnavailable("Package could not be built.") from None

    requester = get_user_by_id(share_request["requester_id"])

    return {
        "request_id": request_id,
        "package": package,
        "fingerprint": fingerprint,
        "requester_username": requester["username"] if requester else "-",
        "category": share_request["category"],
        "expires_at": share_request["expires_at"],
    }


def _no_store(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def _with_package(request_id, build_response):
    owner_id = current_user_id()
    if owner_id is None:
        return redirect(url_for("login"))

    try:
        data = _load_package(owner_id, request_id)
    except ShareAccessError:
        return _no_store(make_response(ACCESS_ERROR_MESSAGE, 404))
    except (_PackageUnavailable, sqlite3.Error):
        return _no_store(make_response(PACKAGE_ERROR_MESSAGE, 503))

    return _no_store(build_response(data))


@grant_bp.route("/requests/<request_id>/package", methods=["GET"])
def key_package(request_id):
    def build_response(data):
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)

        return make_response(
            render_template(
                "share_key.html",
                csrf_token=session["csrf_token"],
                **data,
            )
        )

    return _with_package(request_id, build_response)


@grant_bp.route("/requests/<request_id>/package/download", methods=["GET"])
def download_key_package(request_id):
    def build_response(data):
        return send_file(
            io.BytesIO((data["package"] + "\n").encode("ascii")),
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=f"paket-{data['request_id']}.medimokey",
        )

    return _with_package(request_id, build_response)