
"""Database functions for managing health record sharing requests."""

import sqlite3
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo

from db import get_connection
from share_errors import ShareAccessError


VALID_CATEGORIES = {"profile", "identity", "document", "video"}


def _jakarta_now():
    """Return current Jakarta time in database format."""
    return datetime.now(
        ZoneInfo("Asia/Jakarta")
    ).strftime("%Y-%m-%d %H:%M:%S")


def create_share_request(requester_id, owner_id, category, reason):
    """Create a new sharing request and return its ID."""

    if requester_id == owner_id:
        raise ValueError("Requester and owner must be different.")

    if category not in VALID_CATEGORIES:
        raise ValueError("Invalid sharing category.")

    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("Reason cannot be empty.")

    if len(reason) > 500:
        raise ValueError("Reason cannot exceed 500 characters.")

    request_id = str(uuid.uuid4())

    connection = get_connection()

    try:
        with connection:
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

        return request_id

    finally:
        connection.close()

def approve_share_request(owner_id, request_id, wrapped_key, expires_at):
    """Approve a pending request and store its wrapped sharing key."""

    if not isinstance(wrapped_key, bytes) or not wrapped_key:
        raise ValueError("Wrapped key must be non-empty bytes.")

    if not isinstance(expires_at, str):
        raise ValueError("Expiry time must be a string.")

    try:
        expiry = datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        raise ValueError(
            "Expiry time must use YYYY-MM-DD HH:MM:SS format."
        ) from None

    jakarta_now = datetime.now(ZoneInfo("Asia/Jakarta"))

    if expiry <= jakarta_now.replace(tzinfo=None):
        raise ValueError("Expiry time must be in the future.")

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
                    "Request not found or cannot be approved."
                )

        return True

    finally:
        connection.close()

def reject_share_request(owner_id, request_id):
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
                (
                    _jakarta_now(),
                    request_id,
                    owner_id,
                ),
            )

            if cursor.rowcount != 1:
                raise ShareAccessError(
                    "Request not found or cannot be rejected."
                )

        return True

    finally:
        connection.close()

def get_request_for_owner(owner_id, request_id):
    """Get a sharing request owned by the specified user."""

    connection = get_connection()

    try:
        request = connection.execute(
            """
            SELECT
                id,
                requester_id,
                owner_id,
                category,
                reason,
                status,
                wrapped_key,
                created_at,
                expires_at,
                decided_at
            FROM share_requests
            WHERE id = ? AND owner_id = ?
            """,
            (request_id, owner_id),
        ).fetchone()

        if request is None:
            raise ShareAccessError("Request not found.")

        return request

    finally:
        connection.close()


def get_active_request_for_requester(requester_id, request_id):
    """Get an approved and unexpired request belonging to the requester."""

    connection = get_connection()

    try:
        request = connection.execute(
            """
            SELECT
                id,
                requester_id,
                owner_id,
                category,
                reason,
                status,
                wrapped_key,
                created_at,
                expires_at,
                decided_at
            FROM share_requests
            WHERE
                id = ?
                AND requester_id = ?
                AND status = 'approved'
                AND expires_at IS NOT NULL
                AND expires_at > ?
            """,
            (
                request_id,
                requester_id,
                _jakarta_now(),
            ),
        ).fetchone()

        if request is None:
            raise ShareAccessError(
                "Request is not active or access has expired."
            )

        return request

    finally:
        connection.close()


def record_share_event(request_id, actor_id, action):
    """Record a sharing activity in the audit log."""

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
                (
                    request_id,
                    actor_id,
                    action.strip(),
                ),
            )

            return cursor.lastrowid

    finally:
        connection.close()
