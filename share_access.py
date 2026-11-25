
"""Functions for opening and managing shared health records."""

from crypto_core import decrypt_blob
from file_payload import unpack_file_payload
from share_errors import InvalidKeyPackageError
from share_keys import parse_key_package
from storage import read_envelope


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
    """Open one shared item.

    Full orchestration will be completed when the requester-key and
    sharing-database interfaces are available.
    """
    raise NotImplementedError(
        "Waiting for user-key and share-request database interfaces."
    )


def expire_old_requests():
    """Expire sharing requests whose expiry time has passed."""
    pass


def revoke_request(owner_id, request_id):
    """Revoke an approved sharing request."""
    pass
