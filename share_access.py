"""Functions for opening and managing shared health records."""

from datetime import datetime
from zoneinfo import ZoneInfo

import db

from crypto_core import decrypt_blob
from file_payload import unpack_file_payload
from share_errors import InvalidKeyPackageError, ShareAccessError
from share_keys import parse_key_package
from share_requests import (
    get_active_request_for_requester,
    record_share_event,
)
from storage import delete_envelope, read_envelope
from user_keys import get_public_key, unlock_private_key, unwrap_key

def _validate_key_package(package_text, request_id, recipient_fingerprint):
    """Validate a key package against the request and recipient."""
    package = parse_key_package(package_text)

    if package["request_id"] != request_id:
        raise InvalidKeyPackageError(
            "Key package does not match the requested sharing request."
        )

    if package["recipient_fp"] != recipient_fingerprint:
        raise InvalidKeyPackageError(
            "Key package does not belong to this recipient."
        )

    return package["wrapped_key"]


def _decrypt_shared_envelope(
    storage_name,
    share_key,
    owner_id,
    item_id,
):
    """Read and decrypt one shared copy, returning metadata and file bytes."""
    envelope = read_envelope(storage_name)

    context = {
        "owner_id": owner_id,
        "kind": "share",
        "item_id": item_id,
    }

    payload = decrypt_blob(
        envelope,
        share_key,
        "AES",
        context,
    )

    return unpack_file_payload(payload)


def open_shared_item(
    requester_id,
    request_id,
    item_id,
    package_text,
    password,
):
    """Open one item shared with the authenticated requester."""

    # 1. Expire old requests before checking access.
    expire_old_requests()

    # 2. Confirm the request is approved, unexpired, and belongs
    #    to the current requester.
    shared_request = get_active_request_for_requester(
        requester_id,
        request_id,
    )

    # 3. Get the requester's public key fingerprint.
    key_info = get_public_key(requester_id)

    if key_info is None:
        raise ShareAccessError(
            "Buat kunci di halaman Kunci saya terlebih dahulu."
        )

    # 4. Validate the key package against the request and fingerprint.
    wrapped_key = _validate_key_package(
        package_text,
        request_id,
        key_info["fingerprint"],
    )

    # Ensure the supplied package contains the wrapped key
    # stored for this approved request.
    if wrapped_key != shared_request["wrapped_key"]:
        raise InvalidKeyPackageError(
            "Wrapped key does not match the approved request."
        )

    # 5. Unlock the requester's private key.
    private_key = unlock_private_key(
        requester_id,
        password,
    )

    # 6. Recover the original share key.
    share_key = unwrap_key(
        wrapped_key,
        private_key,
        request_id,
    )

    # 7. Find the requested item within this specific request.
    connection = db.get_connection()

    try:
        item = connection.execute(
            """
            SELECT id, storage_name
            FROM shared_items
            WHERE id = ?
              AND request_id = ?
            """,
            (item_id, request_id),
        ).fetchone()
    finally:
        connection.close()

    if item is None:
        raise ShareAccessError(
            "Shared item is not available."
        )

    # 8. Read and decrypt the shared envelope.
    metadata, file_bytes = _decrypt_shared_envelope(
        item["storage_name"],
        share_key,
        shared_request["owner_id"],
        item_id,
    )

    # 9. Record successful access.
    record_share_event(
        request_id,
        requester_id,
        "opened",
    )

    # 10. Return the decrypted file.
    return metadata, file_bytes



def expire_old_requests():
    """Expire approved sharing requests whose expiry time has passed."""
    now = datetime.now(
        ZoneInfo("Asia/Jakarta")
    ).strftime("%Y-%m-%d %H:%M:%S")

    connection = db.get_connection()

    try:
        # Lock the database transaction while processing expired requests.
        connection.execute("BEGIN IMMEDIATE")

        expired_requests = connection.execute(
            """
            SELECT id
            FROM share_requests
            WHERE status = 'approved'
              AND expires_at IS NOT NULL
              AND expires_at <= ?
            ORDER BY expires_at, id
            """,
            (now,),
        ).fetchall()

        expired_count = 0

        for request in expired_requests:
            request_id = request["id"]

            items = connection.execute(
                """
                SELECT storage_name
                FROM shared_items
                WHERE request_id = ?
                """,
                (request_id,),
            ).fetchall()

            # Delete encrypted copies from storage.
            for item in items:
                delete_envelope(item["storage_name"])

            cursor = connection.execute(
                """
                UPDATE share_requests
                SET status = 'expired',
                    wrapped_key = NULL
                WHERE id = ?
                  AND status = 'approved'
                  AND expires_at IS NOT NULL
                  AND expires_at <= ?
                """,
                (request_id, now),
            )

            if cursor.rowcount != 1:
                continue

            connection.execute(
                """
                DELETE FROM shared_items
                WHERE request_id = ?
                """,
                (request_id,),
            )

            connection.execute(
                """
                INSERT INTO share_audit_log (
                    request_id,
                    actor_id,
                    action
                )
                VALUES (?, NULL, 'expired')
                """,
                (request_id,),
            )

            expired_count += 1

        connection.commit()
        return expired_count

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()





def revoke_request(owner_id, request_id):
    """Revoke an approved sharing request owned by the given user."""
    connection = db.get_connection()

    try:
        connection.execute("BEGIN IMMEDIATE")

        request = connection.execute(
            """
            SELECT id, owner_id, status
            FROM share_requests
            WHERE id = ? AND owner_id = ?
            """,
            (request_id, owner_id),
        ).fetchone()

        if request is None or request["status"] != "approved":
            raise ShareAccessError(
                "Sharing request is not available for revocation."
            )

        items = connection.execute(
            """
            SELECT storage_name
            FROM shared_items
            WHERE request_id = ?
            """,
            (request_id,),
        ).fetchall()

        for item in items:
            delete_envelope(item["storage_name"])

        cursor = connection.execute(
            """
            UPDATE share_requests
            SET status = 'revoked',
                wrapped_key = NULL
            WHERE id = ?
              AND owner_id = ?
              AND status = 'approved'
            """,
            (request_id, owner_id),
        )

        if cursor.rowcount != 1:
            raise ShareAccessError(
                "Sharing request is not available for revocation."
            )

        connection.execute(
            """
            DELETE FROM shared_items
            WHERE request_id = ?
            """,
            (request_id,),
        )

        connection.execute(
            """
            INSERT INTO share_audit_log (
                request_id,
                actor_id,
                action
            )
            VALUES (?, ?, 'revoked')
            """,
            (request_id, owner_id),
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()
