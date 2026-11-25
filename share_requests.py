
"""Database functions for managing health record sharing requests."""

import logging
import sqlite3
import uuid

from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from db import get_connection, get_user_by_username
from share_errors import ShareAccessError
from share_keys import create_share
from storage import delete_envelope
from user_keys import get_public_key


logger = logging.getLogger(__name__)

VALID_CATEGORIES = {"profile", "identity", "document", "video"}
VALID_EXPIRY_DAYS = {1, 7, 30}


def _jakarta_now():
    """Return current Jakarta time in database format."""
    return datetime.now(ZoneInfo("Asia/Jakarta")).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def _parse_datetime(value):
    """Parse a datetime string in the database format."""
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return None


def _is_duplicate_pending_error(exc):
    """Check whether an integrity error is caused by a duplicate pending request."""
    message = str(exc).lower()

    return (
        "share_requests.requester_id" in message
        and "share_requests.owner_id" in message
    )


# ============================================================
# NEW REQUEST FUNCTIONS
# ============================================================

def create_request(requester_id, owner_username, category, reason):
    """Create a sharing request using the owner's username."""

    if (
        isinstance(requester_id, bool)
        or not isinstance(requester_id, int)
        or requester_id <= 0
    ):
        raise ValueError("Invalid requester.")

    if not isinstance(owner_username, str) or not owner_username.strip():
        raise ValueError("Owner username cannot be empty.")

    if category not in VALID_CATEGORIES:
        raise ValueError("Invalid sharing category.")

    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("Reason cannot be empty.")

    if len(reason.strip()) > 500:
        raise ValueError("Reason cannot exceed 500 characters.")

    owner = get_user_by_username(owner_username.strip())

    if owner is None:
        raise ValueError("User not found.")

    owner_id = owner["id"]

    if requester_id == owner_id:
        raise ValueError("You cannot request your own data.")

    if get_public_key(requester_id) is None:
        raise ValueError(
            "You need to generate a keypair before requesting data."
        )

    request_id = str(uuid.uuid4())
    connection = get_connection()

    try:
        with connection:
            try:
                connection.execute(
                    """
                    INSERT INTO share_requests (
                        id,
                        requester_id,
                        owner_id,
                        category,
                        reason
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        request_id,
                        requester_id,
                        owner_id,
                        category,
                        reason.strip(),
                    ),
                )

            except sqlite3.IntegrityError as exc:
                if _is_duplicate_pending_error(exc):
                    raise ValueError(
                        "You already have a pending request "
                        "for this user."
                    ) from None

                raise

            connection.execute(
                """
                INSERT INTO share_audit_log (
                    request_id,
                    actor_id,
                    action
                )
                VALUES (?, ?, ?)
                """,
                (request_id, requester_id, "requested"),
            )

        return request_id

    finally:
        connection.close()


def approve_request(owner_id, request_id, selection, days, master_key):
    """Approve a sharing request and create encrypted shared copies."""

    if isinstance(days, bool) or days not in VALID_EXPIRY_DAYS:
        raise ValueError("Expiry must be 1, 7, or 30 days.")

    request_row = get_request_for_owner(owner_id, request_id)

    if request_row["status"] != "pending":
        raise ShareAccessError("This request is no longer pending.")

    requester_id = request_row["requester_id"]
    category = request_row["category"]

    requester_key = get_public_key(requester_id)

    if requester_key is None:
        raise ShareAccessError(
            "The requester does not have a public key."
        )

    now = datetime.now(ZoneInfo("Asia/Jakarta"))
    expires_at = (
        now + timedelta(days=days)
    ).strftime("%Y-%m-%d %H:%M:%S")

    # Create encrypted copies using the existing share_keys implementation.
    # This function handles cleanup if creating the copies itself fails.
    share_result = create_share(
        owner_id=owner_id,
        request_id=request_id,
        category=category,
        selection=selection,
        requester_public_key_pem=requester_key["public_key_pem"],
        master_key=master_key,
    )

    wrapped_key = share_result["wrapped_key"]
    shared_items = share_result["shared_items"]

    connection = get_connection()

    try:
        with connection:
            cursor = connection.execute(
                """
                UPDATE share_requests
                SET
                    status = 'approved',
                    wrapped_key = ?,
                    expires_at = ?,
                    decided_at = ?
                WHERE
                    id = ?
                    AND owner_id = ?
                    AND status = 'pending'
                """,
                (
                    wrapped_key,
                    expires_at,
                    _jakarta_now(),
                    request_id,
                    owner_id,
                ),
            )

            if cursor.rowcount != 1:
                raise ShareAccessError(
                    "This request is no longer pending."
                )

            for item in shared_items:
                connection.execute(
                    """
                    INSERT INTO shared_items (
                        id,
                        request_id,
                        source_file_id,
                        category,
                        storage_name
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        item["id"],
                        request_id,
                        item["source_file_id"],
                        category,
                        item["storage_name"],
                    ),
                )

            connection.execute(
                """
                INSERT INTO share_audit_log (
                    request_id,
                    actor_id,
                    action
                )
                VALUES (?, ?, ?)
                """,
                (request_id, owner_id, "approved"),
            )

    except Exception:
        # The database transaction failed.
        # Remove all encrypted copies created by create_share().
        for item in shared_items:
            try:
                delete_envelope(item["storage_name"])
            except (OSError, ValueError):
                logger.exception(
                    "Failed to clean up shared envelope: %s",
                    item["storage_name"],
                )

        raise

    finally:
        connection.close()


def reject_request(owner_id, request_id):
    """Reject a pending sharing request."""

    connection = get_connection()

    try:
        with connection:
            cursor = connection.execute(
                """
                UPDATE share_requests
                SET
                    status = 'rejected',
                    decided_at = ?
                WHERE
                    id = ?
                    AND owner_id = ?
                    AND status = 'pending'
                """,
                (_jakarta_now(), request_id, owner_id),
            )

            if cursor.rowcount != 1:
                raise ShareAccessError(
                    "Request not found or no longer pending."
                )

            connection.execute(
                """
                INSERT INTO share_audit_log (
                    request_id,
                    actor_id,
                    action
                )
                VALUES (?, ?, ?)
                """,
                (request_id, owner_id, "rejected"),
            )

        return True

    finally:
        connection.close()


# ============================================================
# REQUEST LIST FUNCTIONS
# ============================================================

def get_incoming_requests(owner_id):
    """Get sharing requests received by the current user."""

    connection = get_connection()

    try:
        return connection.execute(
            """
            SELECT
                sr.id,
                u.username AS requester_username,
                sr.category,
                sr.reason,
                sr.status,
                sr.created_at,
                sr.expires_at
            FROM share_requests AS sr
            JOIN users AS u
                ON u.id = sr.requester_id
            WHERE sr.owner_id = ?
            ORDER BY sr.created_at DESC, sr.id DESC
            """,
            (owner_id,),
        ).fetchall()

    finally:
        connection.close()


def get_outgoing_requests(requester_id):
    """Get sharing requests sent by the current user."""

    connection = get_connection()

    try:
        return connection.execute(
            """
            SELECT
                sr.id,
                u.username AS owner_username,
                sr.category,
                sr.status,
                sr.expires_at
            FROM share_requests AS sr
            JOIN users AS u
                ON u.id = sr.owner_id
            WHERE sr.requester_id = ?
            ORDER BY sr.created_at DESC, sr.id DESC
            """,
            (requester_id,),
        ).fetchall()

    finally:
        connection.close()


# ============================================================
# ACCESS AND AUDIT FUNCTIONS
# ============================================================

def get_request_for_owner(owner_id, request_id):
    """Get a request belonging to the specified owner."""

    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT *
            FROM share_requests
            WHERE id = ? AND owner_id = ?
            """,
            (request_id, owner_id),
        ).fetchone()

        if row is None:
            raise ShareAccessError("Request not found.")

        return row

    finally:
        connection.close()


def get_active_request_for_requester(requester_id, request_id):
    """Get an approved and non-expired request belonging to requester."""

    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT *
            FROM share_requests
            WHERE
                id = ?
                AND requester_id = ?
                AND status = 'approved'
                AND expires_at > ?
            """,
            (request_id, requester_id, _jakarta_now()),
        ).fetchone()

        if row is None:
            raise ShareAccessError(
                "Request is not active or access has expired."
            )

        return row

    finally:
        connection.close()


def record_share_event(request_id, actor_id, action):
    """Record an event in the sharing audit log."""

    if not isinstance(action, str) or not action.strip():
        raise ValueError("Action cannot be empty.")

    connection = get_connection()

    try:
        with connection:
            cursor = connection.execute(
                """
                INSERT INTO share_audit_log (
                    request_id,
                    actor_id,
                    action
                )
                VALUES (?, ?, ?)
                """,
                (request_id, actor_id, action.strip()),
            )

        return cursor.lastrowid

    finally:
        connection.close()


# ============================================================
# LEGACY FUNCTIONS - KEPT FOR BACKWARD COMPATIBILITY
# ============================================================

def create_share_request(requester_id, owner_id, category, reason):
    """Create a sharing request using user IDs (legacy helper)."""

    if requester_id == owner_id:
        raise ValueError("Requester and owner must be different.")

    if category not in VALID_CATEGORIES:
        raise ValueError("Invalid sharing category.")

    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("Reason cannot be empty.")

    if len(reason.strip()) > 500:
        raise ValueError("Reason cannot exceed 500 characters.")

    request_id = str(uuid.uuid4())
    connection = get_connection()

    try:
        with connection:
            # Intentionally do not catch IntegrityError here.
            # Existing tests and legacy callers expect SQLite's error.
            connection.execute(
                """
                INSERT INTO share_requests (
                    id,
                    requester_id,
                    owner_id,
                    category,
                    reason
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    request_id,
                    requester_id,
                    owner_id,
                    category,
                    reason.strip(),
                ),
            )

            connection.execute(
                """
                INSERT INTO share_audit_log (
                    request_id,
                    actor_id,
                    action
                )
                VALUES (?, ?, ?)
                """,
                (request_id, requester_id, "requested"),
            )

        return request_id

    finally:
        connection.close()


def approve_share_request(owner_id, request_id, wrapped_key, expires_at):
    """Approve a request using an existing wrapped key (legacy helper)."""

    if not isinstance(wrapped_key, bytes) or not wrapped_key:
        raise ValueError("Wrapped key must be non-empty bytes.")

    parsed_expiry = _parse_datetime(expires_at)

    if parsed_expiry is None:
        raise ValueError("Invalid expiry datetime.")

    if expires_at <= _jakarta_now():
        raise ValueError("Expiry must be in the future.")

    connection = get_connection()

    try:
        with connection:
            cursor = connection.execute(
                """
                UPDATE share_requests
                SET
                    status = 'approved',
                    wrapped_key = ?,
                    expires_at = ?,
                    decided_at = ?
                WHERE
                    id = ?
                    AND owner_id = ?
                    AND status = 'pending'
                """,
                (
                    wrapped_key,
                    expires_at,
                    _jakarta_now(),
                    request_id,
                    owner_id,
                ),
            )

            if cursor.rowcount != 1:
                raise ShareAccessError(
                    "Request not found or no longer pending."
                )

        return True

    finally:
        connection.close()


def reject_share_request(owner_id, request_id):
    """Legacy helper for rejecting a sharing request."""
    return reject_request(owner_id, request_id)
