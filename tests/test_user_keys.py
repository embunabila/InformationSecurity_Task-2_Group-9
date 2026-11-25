
import unittest

from crypto_core import (
    _encode_context,
    encrypt_blob,
    decrypt_blob,
    InvalidEnvelopeError,
)


class TestContextExtension(unittest.TestCase):

    def setUp(self):
        self.key = bytes(range(32))
        self.data = b"Medimo dummy test data"

        self.private_key_context = {
            "owner_id": 1,
            "kind": "private_key",
            "item_id": "private_key",
        }

        self.share_context = {
            "owner_id": 2,
            "kind": "share",
            "item_id": "550e8400-e29b-41d4-a716-446655440000",
        }

    def test_valid_private_key_context(self):
        result = _encode_context(self.private_key_context)
        self.assertIsInstance(result, bytes)

    def test_valid_share_context(self):
        result = _encode_context(self.share_context)
        self.assertIsInstance(result, bytes)

    def test_invalid_private_key_item_id(self):
        context = {
            **self.private_key_context,
            "item_id": "invalid",
        }

        with self.assertRaises(ValueError):
            _encode_context(context)

    def test_invalid_share_uuid(self):
        context = {
            **self.share_context,
            "item_id": "invalid-uuid",
        }

        with self.assertRaises(ValueError):
            _encode_context(context)

    def test_uppercase_share_uuid(self):
        context = {
            **self.share_context,
            "item_id": self.share_context["item_id"].upper(),
        }

        with self.assertRaises(ValueError):
            _encode_context(context)

    def test_unknown_context_kind(self):
        context = {
            **self.share_context,
            "kind": "unknown",
        }

        with self.assertRaises(ValueError):
            _encode_context(context)

    def test_private_key_aes_round_trip(self):
        encrypted = encrypt_blob(
            self.data,
            self.key,
            "AES",
            self.private_key_context,
        )

        decrypted = decrypt_blob(
            encrypted,
            self.key,
            "AES",
            self.private_key_context,
        )

        self.assertEqual(decrypted, self.data)

    def test_share_aes_round_trip(self):
        encrypted = encrypt_blob(
            self.data,
            self.key,
            "AES",
            self.share_context,
        )

        decrypted = decrypt_blob(
            encrypted,
            self.key,
            "AES",
            self.share_context,
        )

        self.assertEqual(decrypted, self.data)

    def test_different_owner_id(self):
        encrypted = encrypt_blob(
            self.data,
            self.key,
            "AES",
            self.private_key_context,
        )

        wrong_context = {
            **self.private_key_context,
            "owner_id": 99,
        }

        with self.assertRaises(InvalidEnvelopeError):
            decrypt_blob(
                encrypted,
                self.key,
                "AES",
                wrong_context,
            )

    def test_different_share_item_id(self):
        encrypted = encrypt_blob(
            self.data,
            self.key,
            "AES",
            self.share_context,
        )

        wrong_context = {
            **self.share_context,
            "item_id": "550e8400-e29b-41d4-a716-446655440001",
        }

        with self.assertRaises(InvalidEnvelopeError):
            decrypt_blob(
                encrypted,
                self.key,
                "AES",
                wrong_context,
            )

    def test_context_kind_substitution(self):
        encrypted = encrypt_blob(
            self.data,
            self.key,
            "AES",
            self.share_context,
        )

        wrong_context = {
            **self.share_context,
            "kind": "file",
        }

        with self.assertRaises(InvalidEnvelopeError):
            decrypt_blob(
                encrypted,
                self.key,
                "AES",
                wrong_context,
            )

    def test_existing_context_compatibility(self):
        contexts = [
            {
                "owner_id": 1,
                "kind": "profile",
                "item_id": "profile",
            },
            {
                "owner_id": 1,
                "kind": "file",
                "item_id": "550e8400-e29b-41d4-a716-446655440000",
            },
        ]

        for context in contexts:
            with self.subTest(context=context):
                for algorithm in ("AES", "DES", "RC4"):
                    with self.subTest(algorithm=algorithm):
                        encrypted = encrypt_blob(
                            self.data,
                            self.key,
                            algorithm,
                            context,
                        )

                        decrypted = decrypt_blob(
                            encrypted,
                            self.key,
                            algorithm,
                            context,
                        )

                        self.assertEqual(decrypted, self.data)

    def test_private_key_to_profile_substitution(self):
        encrypted = encrypt_blob(
            self.data,
            self.key,
            "AES",
            self.private_key_context,
        )

        wrong_context = {
            "owner_id": self.private_key_context["owner_id"],
            "kind": "profile",
            "item_id": "profile",
        }

        with self.assertRaises(InvalidEnvelopeError):
            decrypt_blob(
                encrypted,
                self.key,
                "AES",
                wrong_context,
            )

    def test_different_share_owner_id(self):
        encrypted = encrypt_blob(
            self.data,
            self.key,
            "AES",
            self.share_context,
        )

        wrong_context = {
            **self.share_context,
            "owner_id": 99,
        }

        with self.assertRaises(InvalidEnvelopeError):
            decrypt_blob(
                encrypted,
                self.key,
                "AES",
                wrong_context,
            )

    def test_context_serialization_is_deterministic(self):
        reordered_context = {
            "item_id": "private_key",
            "kind": "private_key",
            "owner_id": 1,
        }

        self.assertEqual(
            _encode_context(self.private_key_context),
            _encode_context(reordered_context),
        )

    def test_malformed_share_uuid_correct_length(self):
        context = {
            **self.share_context,
            "item_id": "550e8400-e29b-41d4-a716-44665544000z",
        }

        with self.assertRaises(ValueError):
            _encode_context(context)

if __name__ == "__main__":
    unittest.main()
