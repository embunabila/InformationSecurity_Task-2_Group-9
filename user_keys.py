
from uuid import UUID

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey

from share_errors import InvalidKeyPackageError


RSA_KEY_BITS = 3072
SHARE_KEY_SIZE = 32
WRAPPED_KEY_SIZE = RSA_KEY_BITS // 8


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
