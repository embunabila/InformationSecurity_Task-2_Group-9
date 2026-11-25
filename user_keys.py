
from uuid import UUID

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey

from share_errors import InvalidKeyPackageError

from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

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
