"""Create encrypted share copies and the wrapped share key."""

import json
import uuid

from Crypto.Random import get_random_bytes

from crypto_core import decrypt_blob, encrypt_blob
from db import get_health_profile_envelopes, get_medical_file
from file_payload import pack_file_payload
from storage import delete_envelope, read_envelope, write_envelope
from user_keys import wrap_key

SHARE_KEY_SIZE = 32

FILE_CATEGORIES = ("identity", "document", "video")
SHARE_CATEGORIES = ("profile",) + FILE_CATEGORIES

PROFILE_COPY_METADATA = {
    "filename": "profil.json",
    "mime": "application/json",
}


def _validate_owner_id(owner_id):
    if isinstance(owner_id, bool) or not isinstance(owner_id, int) or owner_id <= 0:
        raise ValueError("owner_id must be a positive integer.")


def _validate_uuid(value, name):
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string.")

    try:
        parsed = uuid.UUID(value)
    except ValueError:
        raise ValueError(f"{name} must be a UUID.") from None

    # Only the canonical lowercase form, so the OAEP label is unambiguous.
    if str(parsed) != value:
        raise ValueError(f"{name} must be a lowercase UUID with hyphens.")


def _selected_ids(selection, category):
    """Return the selected file ids or profile fields as a list."""
    expected_key = "profile_fields" if category == "profile" else "file_ids"

    if not isinstance(selection, dict) or set(selection) != {expected_key}:
        raise ValueError(f"selection must contain only {expected_key}.")

    values = selection[expected_key]

    if not isinstance(values, list) or not values:
        raise ValueError(f"{expected_key} must be a non-empty list.")

    if not all(isinstance(value, str) and value for value in values):
        raise ValueError(f"{expected_key} must contain non-empty strings.")

    if len(set(values)) != len(values):
        raise ValueError(f"{expected_key} must not contain duplicates.")

    if category != "profile":
        for file_id in values:
            _validate_uuid(file_id, "file_id")

    return values


def _load_file_payload(owner_id, file_id, category, master_key):
    """Decrypt the owner's AES copy of a file; returns the packed payload."""
    # Query by owner too, so another user's file id is never accepted.
    record = get_medical_file(file_id, owner_id)

    if record is None or record["category"] != category:
        raise ValueError("Selected file is not available for this request.")

    envelope = read_envelope(record["aes_storage_name"])

    return decrypt_blob(
        envelope,
        master_key,
        "AES",
        {"owner_id": owner_id, "kind": "file", "item_id": file_id},
    )


def _load_profile_payload(owner_id, fields, master_key):
    """Decrypt the owner's profile and pack only the selected fields."""
    row = get_health_profile_envelopes(owner_id)

    if row is None:
        raise ValueError("Owner has no health profile.")

    plaintext = decrypt_blob(
        row["aes_envelope"],
        master_key,
        "AES",
        {"owner_id": owner_id, "kind": "profile", "item_id": "profile"},
    )
    profile = json.loads(plaintext.decode("utf-8"))

    if not isinstance(profile, dict):
        raise ValueError("Stored profile has an invalid format.")

    unknown = [field for field in fields if field not in profile]
    if unknown:
        raise ValueError("Selected profile field does not exist.")

    # Keep the profile's own field order.
    selected = {key: value for key, value in profile.items() if key in fields}

    json_bytes = json.dumps(
        selected,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")

    return pack_file_payload(dict(PROFILE_COPY_METADATA), json_bytes)


def create_share(
    owner_id,
    request_id,
    category,
    selection,
    requester_public_key_pem,
    master_key,
):
    """Encrypt fresh copies of the selected data under a new share key.

    The share key is only returned wrapped with the requester's public key.
    On any failure, copies already written to storage are deleted.
    """
    _validate_owner_id(owner_id)
    _validate_uuid(request_id, "request_id")

    if category not in SHARE_CATEGORIES:
        raise ValueError("Invalid share category.")

    selected = _selected_ids(selection, category)

    # One fresh key per approved request (CSPRNG).
    share_key = get_random_bytes(SHARE_KEY_SIZE)

    # Wrap first: a bad public key fails before anything is written.
    wrapped_key = wrap_key(share_key, requester_public_key_pem, request_id)

    # None stands for the single profile copy.
    sources = [None] if category == "profile" else selected
    shared_items = []

    try:
        # One item at a time, so at most one large file is in memory.
        for source_file_id in sources:
            if source_file_id is None:
                payload = _load_profile_payload(owner_id, selected, master_key)
            else:
                payload = _load_file_payload(
                    owner_id, source_file_id, category, master_key
                )

            item_id = str(uuid.uuid4())
            envelope = encrypt_blob(
                payload,
                share_key,
                "AES",
                {"owner_id": owner_id, "kind": "share", "item_id": item_id},
            )

            storage_name = uuid.uuid4().hex + ".bin"
            write_envelope(storage_name, envelope)

            shared_items.append(
                {
                    "id": item_id,
                    "source_file_id": source_file_id,
                    "storage_name": storage_name,
                }
            )
    except Exception:
        for item in shared_items:
            try:
                delete_envelope(item["storage_name"])
            except (OSError, ValueError):
                pass
        raise

    return {"wrapped_key": wrapped_key, "shared_items": shared_items}