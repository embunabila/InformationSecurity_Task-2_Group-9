import sqlite3
from contextlib import closing
from uuid import UUID

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import scrypt
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Random import get_random_bytes
from werkzeug.security import check_password_hash

from crypto_core import encrypt_blob
from db import get_connection

from share_errors import (
    InvalidKeyPackageError,
    KeyUnlockError,
)

RSA_KEY_BITS = 3072
SHARE_KEY_SIZE = 32
WRAPPED_KEY_SIZE = RSA_KEY_BITS // 8

KEK_SIZE = 32
KEK_SALT_SIZE = 16
SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1

def _generate_kek_salt() -> bytes:
    """Generate a random salt for KEK derivation."""
    return get_random_bytes(KEK_SALT_SIZE)


def _derive_kek(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte KEK from a login password using scrypt."""

    if not isinstance(password, str):
        raise ValueError("Password must be a string.")

    if not password:
        raise ValueError("Password must not be empty.")

    if not isinstance(salt, bytes):
        raise ValueError("KEK salt must be bytes.")

    if len(salt) != KEK_SALT_SIZE:
        raise ValueError("KEK salt must be 16 bytes.")

    return scrypt(
        password.encode("utf-8"),
        salt,
        key_len=KEK_SIZE,
        N=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )

def _private_key_context(user_id: int) -> dict:
    """Build the authenticated context for a user's private key."""

    if (
        isinstance(user_id, bool)
        or not isinstance(user_id, int)
        or user_id <= 0
    ):
        raise ValueError("User ID must be a positive integer.")

    return {
        "owner_id": user_id,
        "kind": "private_key",
        "item_id": "private_key",
    }

def _load_public_key(public_key_pem) -> RsaKey:
    """Import and validate a Medimo RSA public key."""

    if not isinstance(public_key_pem, (str, bytes)):
        raise ValueError("Invalid RSA public key.")

    try:
        public_key = RSA.import_key(public_key_pem)
    except (ValueError, IndexError, TypeError):
        raise ValueError("Invalid RSA public key.") from None

    if public_key.has_private():
        raise ValueError("Expected a public key, not a private key.")

    if public_key.size_in_bits() != RSA_KEY_BITS:
        raise ValueError("RSA public key must be 3072 bits.")

    return public_key


def _request_label(request_id) -> bytes:
    """Validate a canonical UUID and encode it as an OAEP label."""

    if not isinstance(request_id, str):
        raise ValueError("Request ID must be a string.")

    try:
        parsed_id = UUID(request_id)
    except ValueError:
        raise ValueError("Invalid request ID.") from None

    if str(parsed_id) != request_id:
        raise ValueError("Request ID must be a canonical lowercase UUID.")

    return request_id.encode("ascii")


def public_key_fingerprint(public_key_pem) -> str:
    """Generate a SHA-256 fingerprint from the public key DER."""

    public_key = _load_public_key(public_key_pem)

    public_der = public_key.export_key(format="DER")

    digest = SHA256.new(public_der).hexdigest().upper()

    return " ".join(
        digest[i:i + 4]
        for i in range(0, len(digest), 4)
    )


def wrap_key(share_key, public_key_pem, request_id) -> bytes:
    """Encrypt a share key using RSA-OAEP with SHA-256."""

    if not isinstance(share_key, bytes):
        raise ValueError("Share key must be bytes.")

    if len(share_key) != SHARE_KEY_SIZE:
        raise ValueError("Share key must be 32 bytes.")

    public_key = _load_public_key(public_key_pem)
    label = _request_label(request_id)

    cipher = PKCS1_OAEP.new(
        public_key,
        hashAlgo=SHA256,
        label=label,
    )

    return cipher.encrypt(share_key)


def unwrap_key(wrapped_key, private_key, request_id) -> bytes:
    """Decrypt a wrapped share key using the recipient's private key."""

    try:
        if not isinstance(wrapped_key, bytes):
            raise ValueError("Wrapped key must be bytes.")

        if len(wrapped_key) != WRAPPED_KEY_SIZE:
            raise ValueError("Invalid wrapped key length.")

        if not isinstance(private_key, RsaKey):
            raise ValueError("Invalid RSA private key.")

        if not private_key.has_private():
            raise ValueError("RSA private key is required.")

        if private_key.size_in_bits() != RSA_KEY_BITS:
            raise ValueError("RSA private key must be 3072 bits.")

        label = _request_label(request_id)

        cipher = PKCS1_OAEP.new(
            private_key,
            hashAlgo=SHA256,
            label=label,
        )

        share_key = cipher.decrypt(wrapped_key)

        if len(share_key) != SHARE_KEY_SIZE:
            raise ValueError("Invalid share key length.")

        return share_key

    except (ValueError, TypeError):
        raise InvalidKeyPackageError(
            "Invalid key package."
        ) from None


def get_public_key(user_id) -> dict | None:
    """Return a user's public key and fingerprint, if available."""

    _private_key_context(user_id)

    with closing(get_connection()) as connection:
        row = connection.execute(
            """
            SELECT public_key_pem, fingerprint
            FROM user_keys
            WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()

    if row is None:
        return None

    return {
        "public_key_pem": row["public_key_pem"],
        "fingerprint": row["fingerprint"],
    }

def generate_user_keypair(user_id, password) -> None:
    """Generate and securely store a user's RSA-3072 keypair."""

    context = _private_key_context(user_id)

    if not isinstance(password, str) or not password:
        raise KeyUnlockError("Password verification failed.")

    # Read the account and check whether a keypair already exists.
    with closing(get_connection()) as connection:
        user = connection.execute(
            """
            SELECT password_hash
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()

        if user is None:
            raise ValueError("User does not exist.")

        existing_key = connection.execute(
            """
            SELECT 1
            FROM user_keys
            WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()

        if existing_key is not None:
            raise ValueError("User already has a keypair.")

    # Verify the submitted password against the login password hash.
    if not check_password_hash(
        user["password_hash"],
        password,
    ):
        raise KeyUnlockError("Password verification failed.")

    # Generate the RSA-3072 keypair.
    private_key = RSA.generate(RSA_KEY_BITS)

    public_key_pem = (
        private_key.public_key()
        .export_key(format="PEM")
        .decode("ascii")
    )

    fingerprint = public_key_fingerprint(public_key_pem)

    # Generate a fresh salt and derive the KEK.
    salt = _generate_kek_salt()
    kek = _derive_kek(password, salt)

    # Export the private key and protect it with the AES envelope.
    private_der = private_key.export_key(
        format="DER",
        pkcs=8,
    )

    encrypted_private_key = encrypt_blob(
        private_der,
        kek,
        "AES",
        context,
    )

    # Remove local references to sensitive key material.
    del private_der, kek, private_key

    # Persist only public information and encrypted private key data.
    with closing(get_connection()) as connection:
        try:
            with connection:
                connection.execute("BEGIN IMMEDIATE")

                # Prevent duplicate generation by concurrent requests.
                existing_key = connection.execute(
                    """
                    SELECT 1
                    FROM user_keys
                    WHERE user_id = ?
                    """,
                    (user_id,),
                ).fetchone()

                if existing_key is not None:
                    raise ValueError(
                        "User already has a keypair."
                    )

                # Ensure the verified account has not changed.
                current_user = connection.execute(
                    """
                    SELECT password_hash
                    FROM users
                    WHERE id = ?
                    """,
                    (user_id,),
                ).fetchone()

                if (
                    current_user is None
                    or current_user["password_hash"]
                    != user["password_hash"]
                ):
                    raise KeyUnlockError(
                        "Password verification failed."
                    )

                connection.execute(
                    """
                    INSERT INTO user_keys (
                        user_id,
                        public_key_pem,
                        fingerprint,
                        private_key_salt,
                        encrypted_private_key
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        user_id,
                        public_key_pem,
                        fingerprint,
                        salt,
                        encrypted_private_key,
                    ),
                )

        except sqlite3.IntegrityError as exc:
            if (
                exc.sqlite_errorcode
                == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
            ):
                raise ValueError(
                    "User already has a keypair."
                ) from None

            raise