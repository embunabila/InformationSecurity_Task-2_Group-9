
import unittest

import hashlib

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from share_errors import InvalidKeyPackageError

from user_keys import (
    public_key_fingerprint,
    wrap_key,
    unwrap_key,
)

from crypto_core import (
    _encode_context,
    encrypt_blob,
    decrypt_blob,
    InvalidEnvelopeError,
)

from unittest.mock import patch

from user_keys import (
    _generate_kek_salt,
    _derive_kek,
    KEK_SIZE,
    KEK_SALT_SIZE,
    SCRYPT_N,
    SCRYPT_R,
    SCRYPT_P,
)

import sqlite3
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory

from werkzeug.security import generate_password_hash

import db
from share_errors import KeyUnlockError

from user_keys import (
    generate_user_keypair,
    get_public_key,
    _private_key_context,
)

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier

from share_errors import KeyLockedError

from user_keys import (
    unlock_private_key,
    MAX_FAILED_UNLOCK_ATTEMPTS,
    LOCKOUT_DURATION_MINUTES,
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


class TestRSAPrimitives(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.private_key = RSA.generate(3072)

        cls.public_key_pem = (
            cls.private_key.public_key()
            .export_key(format="PEM")
            .decode("ascii")
        )

        cls.other_private_key = RSA.generate(3072)

        cls.other_public_key_pem = (
            cls.other_private_key.public_key()
            .export_key(format="PEM")
            .decode("ascii")
        )

        cls.short_private_key = RSA.generate(2048)

        cls.short_public_key_pem = (
            cls.short_private_key.public_key()
            .export_key(format="PEM")
            .decode("ascii")
        )

        cls.share_key = bytes(range(32))

        cls.request_id = (
            "550e8400-e29b-41d4-a716-446655440000"
        )

        cls.other_request_id = (
            "550e8400-e29b-41d4-a716-446655440001"
        )

    def test_fingerprint_format(self):
        fingerprint = public_key_fingerprint(
            self.public_key_pem
        )

        self.assertEqual(len(fingerprint), 79)

        self.assertRegex(
            fingerprint,
            r"^[0-9A-F]{4}( [0-9A-F]{4}){15}$",
        )

    def test_fingerprint_consistency(self):
        first = public_key_fingerprint(
            self.public_key_pem
        )

        second = public_key_fingerprint(
            self.public_key_pem
        )

        self.assertEqual(first, second)

    def test_fingerprint_pem_formatting_independence(self):
        reformatted_pem = self.public_key_pem.replace(
            "\n", "\r\n"
        )

        self.assertEqual(
            public_key_fingerprint(self.public_key_pem),
            public_key_fingerprint(reformatted_pem),
        )

    def test_fingerprint_matches_der_sha256(self):
        public_der = (
            self.private_key.public_key()
            .export_key(format="DER")
        )

        expected = hashlib.sha256(
            public_der
        ).hexdigest().upper()

        actual = public_key_fingerprint(
            self.public_key_pem
        ).replace(" ", "")

        self.assertEqual(actual, expected)

    def test_different_public_keys_have_different_fingerprints(self):
        first = public_key_fingerprint(
            self.public_key_pem
        )

        second = public_key_fingerprint(
            self.other_public_key_pem
        )

        self.assertNotEqual(first, second)

    def test_invalid_public_key(self):
        with self.assertRaises(ValueError):
            public_key_fingerprint("invalid-key")

        with self.assertRaises(ValueError):
            wrap_key(
                self.share_key,
                "invalid-key",
                self.request_id,
            )

    def test_wrap_unwrap_round_trip(self):
        wrapped = wrap_key(
            self.share_key,
            self.public_key_pem,
            self.request_id,
        )

        self.assertIsInstance(wrapped, bytes)
        self.assertEqual(len(wrapped), 384)

        recovered = unwrap_key(
            wrapped,
            self.private_key,
            self.request_id,
        )

        self.assertEqual(recovered, self.share_key)

    def test_randomized_wrapping(self):
        first = wrap_key(
            self.share_key,
            self.public_key_pem,
            self.request_id,
        )

        second = wrap_key(
            self.share_key,
            self.public_key_pem,
            self.request_id,
        )

        self.assertNotEqual(first, second)

        for wrapped in (first, second):
            self.assertEqual(
                unwrap_key(
                    wrapped,
                    self.private_key,
                    self.request_id,
                ),
                self.share_key,
            )

    def test_wrong_private_key(self):
        wrapped = wrap_key(
            self.share_key,
            self.public_key_pem,
            self.request_id,
        )

        with self.assertRaises(InvalidKeyPackageError):
            unwrap_key(
                wrapped,
                self.other_private_key,
                self.request_id,
            )

    def test_wrong_request_id(self):
        wrapped = wrap_key(
            self.share_key,
            self.public_key_pem,
            self.request_id,
        )

        with self.assertRaises(InvalidKeyPackageError):
            unwrap_key(
                wrapped,
                self.private_key,
                self.other_request_id,
            )

    def test_tampered_ciphertext(self):
        wrapped = wrap_key(
            self.share_key,
            self.public_key_pem,
            self.request_id,
        )

        tampered = bytearray(wrapped)
        tampered[len(tampered) // 2] ^= 0x01

        with self.assertRaises(InvalidKeyPackageError):
            unwrap_key(
                bytes(tampered),
                self.private_key,
                self.request_id,
            )

    def test_invalid_share_key_length(self):
        for length in (0, 16, 31, 33, 64):
            with self.subTest(length=length):
                with self.assertRaises(ValueError):
                    wrap_key(
                        bytes(length),
                        self.public_key_pem,
                        self.request_id,
                    )

    def test_invalid_wrapped_key_length(self):
        for length in (0, 32, 383, 385):
            with self.subTest(length=length):
                with self.assertRaises(InvalidKeyPackageError):
                    unwrap_key(
                        bytes(length),
                        self.private_key,
                        self.request_id,
                    )

    def test_invalid_recovered_share_key_length(self):
        cipher = PKCS1_OAEP.new(
            self.private_key.public_key(),
            hashAlgo=SHA256,
            label=self.request_id.encode("ascii"),
        )

        wrapped = cipher.encrypt(bytes(16))

        with self.assertRaises(InvalidKeyPackageError):
            unwrap_key(
                wrapped,
                self.private_key,
                self.request_id,
            )

    def test_invalid_rsa_public_key_size(self):
        with self.assertRaises(ValueError):
            wrap_key(
                self.share_key,
                self.short_public_key_pem,
                self.request_id,
            )

        with self.assertRaises(ValueError):
            public_key_fingerprint(
                self.short_public_key_pem
            )

    def test_invalid_rsa_private_key_size(self):
        wrapped = wrap_key(
            self.share_key,
            self.public_key_pem,
            self.request_id,
        )

        with self.assertRaises(InvalidKeyPackageError):
            unwrap_key(
                wrapped,
                self.short_private_key,
                self.request_id,
            )

    def test_public_key_used_for_unwrapping(self):
        wrapped = wrap_key(
            self.share_key,
            self.public_key_pem,
            self.request_id,
        )

        with self.assertRaises(InvalidKeyPackageError):
            unwrap_key(
                wrapped,
                self.private_key.public_key(),
                self.request_id,
            )

    def test_invalid_request_id(self):
        invalid_ids = (
            "",
            "invalid",
            self.request_id.upper(),
            self.request_id.replace("-", ""),
            None,
        )

        wrapped = wrap_key(
            self.share_key,
            self.public_key_pem,
            self.request_id,
        )

        for request_id in invalid_ids:
            with self.subTest(request_id=request_id):
                with self.assertRaises(ValueError):
                    wrap_key(
                        self.share_key,
                        self.public_key_pem,
                        request_id,
                    )

                with self.assertRaises(InvalidKeyPackageError):
                    unwrap_key(
                        wrapped,
                        self.private_key,
                        request_id,
                    )

    def test_private_key_supplied_as_public_input(self):
        private_pem = self.private_key.export_key(
            format="PEM"
        )

        with self.assertRaises(ValueError):
            public_key_fingerprint(private_pem)

        with self.assertRaises(ValueError):
            wrap_key(
                self.share_key,
                private_pem,
                self.request_id,
            )

    def test_invalid_input_types(self):
        with self.assertRaises(ValueError):
            wrap_key(
                "not-bytes",
                self.public_key_pem,
                self.request_id,
            )

        with self.assertRaises(ValueError):
            public_key_fingerprint(None)

        with self.assertRaises(InvalidKeyPackageError):
            unwrap_key(
                "not-bytes",
                self.private_key,
                self.request_id,
            )

        with self.assertRaises(InvalidKeyPackageError):
            unwrap_key(
                bytes(384),
                None,
                self.request_id,
            )

    def test_library_interoperability(self):
        label = self.request_id.encode("ascii")

        wrapped = wrap_key(
            self.share_key,
            self.public_key_pem,
            self.request_id,
        )

        library_decryptor = PKCS1_OAEP.new(
            self.private_key,
            hashAlgo=SHA256,
            label=label,
        )

        self.assertEqual(
            library_decryptor.decrypt(wrapped),
            self.share_key,
        )

        library_encryptor = PKCS1_OAEP.new(
            self.private_key.public_key(),
            hashAlgo=SHA256,
            label=label,
        )

        library_wrapped = library_encryptor.encrypt(
            self.share_key
        )

        self.assertEqual(
            unwrap_key(
                library_wrapped,
                self.private_key,
                self.request_id,
            ),
            self.share_key,
        )

class TestKEKDerivation(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.password = "MedimoDummyPassword123!"
        cls.salt = bytes(range(16))
        cls.kek = _derive_kek(cls.password, cls.salt)

    def test_scrypt_parameters(self):
        self.assertEqual(SCRYPT_N, 2**17)
        self.assertEqual(SCRYPT_R, 8)
        self.assertEqual(SCRYPT_P, 1)
        self.assertEqual(KEK_SIZE, 32)
        self.assertEqual(KEK_SALT_SIZE, 16)

    def test_random_salt_format(self):
        salt = _generate_kek_salt()
        self.assertIsInstance(salt, bytes)
        self.assertEqual(len(salt), 16)

    def test_random_salts_are_different(self):
        salts = {
            _generate_kek_salt()
            for _ in range(10)
        }
        self.assertEqual(len(salts), 10)

    def test_kek_output_format(self):
        self.assertIsInstance(self.kek, bytes)
        self.assertEqual(len(self.kek), 32)

    def test_deterministic_kek_derivation(self):
        result = _derive_kek(self.password, self.salt)
        self.assertEqual(result, self.kek)

    def test_different_password_produces_different_kek(self):
        result = _derive_kek(
            "DifferentDummyPassword123!",
            self.salt,
        )
        self.assertNotEqual(result, self.kek)

    def test_different_salt_produces_different_kek(self):
        result = _derive_kek(
            self.password,
            bytes(range(1, 17)),
        )
        self.assertNotEqual(result, self.kek)

    def test_scrypt_library_interoperability(self):
        expected = hashlib.scrypt(
            self.password.encode("utf-8"),
            salt=self.salt,
            n=2**17,
            r=8,
            p=1,
            dklen=32,
            maxmem=256 * 1024 * 1024,
        )
        self.assertEqual(self.kek, expected)

    def test_invalid_password_type(self):
        with patch("user_keys.scrypt") as mocked_scrypt:
            for password in (None, 123, b"password"):
                with self.subTest(password=password):
                    with self.assertRaises(ValueError):
                        _derive_kek(password, self.salt)

            mocked_scrypt.assert_not_called()

    def test_empty_password(self):
        with patch("user_keys.scrypt") as mocked_scrypt:
            with self.assertRaises(ValueError):
                _derive_kek("", self.salt)

            mocked_scrypt.assert_not_called()

    def test_invalid_salt(self):
        invalid_salts = (
            None,
            "invalid",
            bytearray(16),
            b"",
            bytes(15),
            bytes(17),
        )

        with patch("user_keys.scrypt") as mocked_scrypt:
            for salt in invalid_salts:
                with self.subTest(salt=salt):
                    with self.assertRaises(ValueError):
                        _derive_kek(self.password, salt)

            mocked_scrypt.assert_not_called()

    def test_utf8_and_scrypt_arguments(self):
        password = "Medimo密码123!"

        with patch(
            "user_keys.scrypt",
            return_value=bytes(32),
        ) as mocked_scrypt:

            result = _derive_kek(password, self.salt)

            mocked_scrypt.assert_called_once_with(
                password.encode("utf-8"),
                self.salt,
                key_len=32,
                N=2**17,
                r=8,
                p=1,
            )

            self.assertEqual(result, bytes(32))


class TestUserKeypairStorage(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.password = "MedimoDummyPassword123!"

        cls.password_hash = generate_password_hash(
            cls.password,
            method="scrypt:131072:8:1",
        )

        cls.other_password = "AnotherDummyPassword456!"

        cls.other_password_hash = generate_password_hash(
            cls.other_password,
            method="scrypt:131072:8:1",
        )

    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.db_path = (
            Path(self.temp_dir.name) / "test_medimo.db"
        )

        self.db_patch = patch.object(
            db,
            "DB_PATH",
            self.db_path,
        )

        self.db_patch.start()
        self.addCleanup(self.db_patch.stop)

        db.init_db()

        with closing(db.get_connection()) as connection:
            with connection:
                connection.execute(
                    """
                    INSERT INTO users (
                        id, username, password_hash
                    )
                    VALUES (?, ?, ?)
                    """,
                    (1, "dummy_user", self.password_hash),
                )

                connection.execute(
                    """
                    INSERT INTO users (
                        id, username, password_hash
                    )
                    VALUES (?, ?, ?)
                    """,
                    (
                        2,
                        "other_user",
                        self.other_password_hash,
                    ),
                )

        self.user_id = 1
        self.other_user_id = 2

    def _read_keypair(self, user_id):
        with closing(db.get_connection()) as connection:
            return connection.execute(
                """
                SELECT *
                FROM user_keys
                WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()

    def _keypair_count(self):
        with closing(db.get_connection()) as connection:
            return connection.execute(
                "SELECT COUNT(*) FROM user_keys"
            ).fetchone()[0]

    def _generate_keypair(self):
        generate_user_keypair(
            self.user_id,
            self.password,
        )

        row = self._read_keypair(self.user_id)

        self.assertIsNotNone(row)

        return row

    def _decrypt_private_der(self, row, password):
        kek = _derive_kek(
            password,
            row["private_key_salt"],
        )

        context = _private_key_context(row["user_id"])

        return decrypt_blob(
            row["encrypted_private_key"],
            kek,
            "AES",
            context,
        )

    def test_generate_keypair_success(self):
        result = generate_user_keypair(
            self.user_id,
            self.password,
        )

        self.assertIsNone(result)
        self.assertIsNotNone(
            self._read_keypair(self.user_id)
        )
        self.assertEqual(self._keypair_count(), 1)

    def test_get_public_key_without_keypair(self):
        self.assertIsNone(
            get_public_key(self.user_id)
        )

    def test_get_public_key_unknown_user(self):
        self.assertIsNone(get_public_key(999))

    def test_get_public_key_returns_only_public_data(self):
        row = self._generate_keypair()

        result = get_public_key(self.user_id)

        self.assertEqual(
            result,
            {
                "public_key_pem": row["public_key_pem"],
                "fingerprint": row["fingerprint"],
            },
        )

        self.assertEqual(
            set(result),
            {"public_key_pem", "fingerprint"},
        )

    def test_generated_public_key_is_rsa3072(self):
        row = self._generate_keypair()

        public_key = RSA.import_key(
            row["public_key_pem"]
        )

        self.assertIsInstance(
            row["public_key_pem"],
            str,
        )

        self.assertEqual(
            public_key.size_in_bits(),
            3072,
        )

        self.assertFalse(public_key.has_private())

        self.assertTrue(
            row["public_key_pem"].startswith(
                "-----BEGIN PUBLIC KEY-----"
            )
        )

    def test_stored_fingerprint_matches_public_key(self):
        row = self._generate_keypair()

        expected = public_key_fingerprint(
            row["public_key_pem"]
        )

        self.assertEqual(
            row["fingerprint"],
            expected,
        )

    def test_stored_salt_is_16_bytes(self):
        row = self._generate_keypair()

        salt = row["private_key_salt"]

        self.assertIsInstance(salt, bytes)
        self.assertEqual(len(salt), 16)

    def test_private_key_is_stored_as_aes_envelope(self):
        row = self._generate_keypair()

        encrypted = row["encrypted_private_key"]

        self.assertIsInstance(encrypted, bytes)

        self.assertEqual(encrypted[:4], b"MDMO")
        self.assertEqual(encrypted[4], 1)
        self.assertEqual(encrypted[5], 1)

        # The encrypted envelope is not an importable RSA key.
        with self.assertRaises(
            (ValueError, IndexError, TypeError)
        ):
            RSA.import_key(encrypted)

    def test_private_key_decrypts_and_matches_public_key(self):
        row = self._generate_keypair()

        private_der = self._decrypt_private_der(
            row,
            self.password,
        )

        private_key = RSA.import_key(private_der)

        self.assertTrue(private_key.has_private())
        self.assertEqual(
            private_key.size_in_bits(),
            3072,
        )

        expected_public_pem = (
            private_key.public_key()
            .export_key(format="PEM")
            .decode("ascii")
        )

        self.assertEqual(
            expected_public_pem,
            row["public_key_pem"],
        )

        self.assertEqual(
            private_der,
            private_key.export_key(
                format="DER",
                pkcs=8,
            ),
        )

        self.assertNotEqual(
            row["encrypted_private_key"],
            private_der,
        )

    def test_wrong_password_rejects_generation(self):
        with patch("user_keys.RSA.generate") as mocked_rsa:
            with patch("user_keys._derive_kek") as mocked_kek:

                with self.assertRaises(KeyUnlockError):
                    generate_user_keypair(
                        self.user_id,
                        "WrongPassword123!",
                    )

                mocked_rsa.assert_not_called()
                mocked_kek.assert_not_called()

        self.assertEqual(self._keypair_count(), 0)

    def test_invalid_password_rejects_generation(self):
        with patch("user_keys.RSA.generate") as mocked_rsa:
            for password in ("", None, 123, b"password"):
                with self.subTest(password=password):
                    with self.assertRaises(KeyUnlockError):
                        generate_user_keypair(
                            self.user_id,
                            password,
                        )

            mocked_rsa.assert_not_called()

        self.assertEqual(self._keypair_count(), 0)

    def test_unknown_user_rejects_generation(self):
        with patch("user_keys.RSA.generate") as mocked_rsa:
            with self.assertRaises(ValueError):
                generate_user_keypair(
                    999,
                    self.password,
                )

            mocked_rsa.assert_not_called()

        self.assertEqual(self._keypair_count(), 0)

    def test_duplicate_keypair_is_rejected_without_overwrite(self):
        original_row = dict(self._generate_keypair())

        with patch("user_keys.RSA.generate") as mocked_rsa:
            with self.assertRaises(ValueError):
                generate_user_keypair(
                    self.user_id,
                    self.password,
                )

            mocked_rsa.assert_not_called()

        current_row = dict(
            self._read_keypair(self.user_id)
        )

        self.assertEqual(current_row, original_row)
        self.assertEqual(self._keypair_count(), 1)

    def test_wrong_password_cannot_decrypt_private_key(self):
        row = self._generate_keypair()

        wrong_kek = _derive_kek(
            "WrongPassword123!",
            row["private_key_salt"],
        )

        with self.assertRaises(InvalidEnvelopeError):
            decrypt_blob(
                row["encrypted_private_key"],
                wrong_kek,
                "AES",
                _private_key_context(self.user_id),
            )

    def test_wrong_owner_context_rejects_private_key(self):
        row = self._generate_keypair()

        kek = _derive_kek(
            self.password,
            row["private_key_salt"],
        )

        wrong_context = _private_key_context(
            self.other_user_id
        )

        with self.assertRaises(InvalidEnvelopeError):
            decrypt_blob(
                row["encrypted_private_key"],
                kek,
                "AES",
                wrong_context,
            )

    def test_tampered_private_key_envelope_is_rejected(self):
        row = self._generate_keypair()

        kek = _derive_kek(
            self.password,
            row["private_key_salt"],
        )

        tampered = bytearray(
            row["encrypted_private_key"]
        )

        tampered[-1] ^= 0x01

        with self.assertRaises(InvalidEnvelopeError):
            decrypt_blob(
                bytes(tampered),
                kek,
                "AES",
                _private_key_context(self.user_id),
            )

    def test_initial_lockout_state(self):
        row = self._generate_keypair()

        self.assertEqual(
            row["failed_unlock_count"],
            0,
        )

        self.assertIsNone(row["locked_until"])
        self.assertIsNotNone(row["created_at"])

    def test_different_users_have_independent_keypairs(self):
        first_row = self._generate_keypair()

        generate_user_keypair(
            self.other_user_id,
            self.other_password,
        )

        second_row = self._read_keypair(
            self.other_user_id
        )

        self.assertEqual(self._keypair_count(), 2)

        self.assertNotEqual(
            first_row["public_key_pem"],
            second_row["public_key_pem"],
        )

        self.assertNotEqual(
            first_row["fingerprint"],
            second_row["fingerprint"],
        )

        self.assertNotEqual(
            first_row["private_key_salt"],
            second_row["private_key_salt"],
        )

    def test_encryption_failure_does_not_store_keypair(self):
        with patch(
            "user_keys.encrypt_blob",
            side_effect=RuntimeError("Simulated failure"),
        ):
            with self.assertRaises(RuntimeError):
                generate_user_keypair(
                    self.user_id,
                    self.password,
                )

        self.assertEqual(self._keypair_count(), 0)

    def test_database_failure_does_not_store_keypair(self):
        with closing(db.get_connection()) as connection:
            with connection:
                connection.execute(
                    """
                    CREATE TRIGGER reject_test_keypair
                    BEFORE INSERT ON user_keys
                    BEGIN
                        SELECT RAISE(
                            ABORT,
                            'Simulated database failure'
                        );
                    END;
                    """
                )

        with self.assertRaises(sqlite3.IntegrityError):
            generate_user_keypair(
                self.user_id,
                self.password,
            )

        self.assertEqual(self._keypair_count(), 0)


class TestPrivateKeyUnlock(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.user_id = 1
        cls.password = "MedimoDummyPassword123!"
        cls.wrong_password = "WrongDummyPassword123!"

        cls.now = datetime(
            2026, 11, 25, 12, 0, 0,
            tzinfo=timezone.utc,
        )

        cls.password_hash = generate_password_hash(
            cls.password,
            method="scrypt:131072:8:1",
        )

        cls.private_key = RSA.generate(3072)

        cls.public_key_pem = (
            cls.private_key.public_key()
            .export_key(format="PEM")
            .decode("ascii")
        )

        cls.fingerprint = public_key_fingerprint(
            cls.public_key_pem
        )

        cls.salt = _generate_kek_salt()

        kek = _derive_kek(
            cls.password,
            cls.salt,
        )

        private_der = cls.private_key.export_key(
            format="DER",
            pkcs=8,
        )

        cls.encrypted_private_key = encrypt_blob(
            private_der,
            kek,
            "AES",
            _private_key_context(cls.user_id),
        )

        del kek, private_der

    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.db_path = (
            Path(self.temp_dir.name) / "test_medimo.db"
        )

        self.db_patch = patch.object(
            db,
            "DB_PATH",
            self.db_path,
        )

        self.db_patch.start()
        self.addCleanup(self.db_patch.stop)

        db.init_db()

        self.clock_patch = patch(
            "user_keys._utc_now",
            return_value=self.now,
        )

        self.mocked_clock = self.clock_patch.start()
        self.addCleanup(self.clock_patch.stop)

        with closing(db.get_connection()) as connection:
            with connection:
                connection.execute(
                    """
                    INSERT INTO users (
                        id, username, password_hash
                    )
                    VALUES (?, ?, ?)
                    """,
                    (
                        self.user_id,
                        "dummy_unlock_user",
                        self.password_hash,
                    ),
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
                        self.user_id,
                        self.public_key_pem,
                        self.fingerprint,
                        self.salt,
                        self.encrypted_private_key,
                    ),
                )

    def _read_row(self):
        with closing(db.get_connection()) as connection:
            return connection.execute(
                """
                SELECT *
                FROM user_keys
                WHERE user_id = ?
                """,
                (self.user_id,),
            ).fetchone()

    def _read_state(self):
        row = self._read_row()

        return (
            row["failed_unlock_count"],
            row["locked_until"],
        )

    def _set_state(self, count, locked_until=None):
        with closing(db.get_connection()) as connection:
            with connection:
                connection.execute(
                    """
                    UPDATE user_keys
                    SET
                        failed_unlock_count = ?,
                        locked_until = ?
                    WHERE user_id = ?
                    """,
                    (
                        count,
                        locked_until,
                        self.user_id,
                    ),
                )

    def _replace_encrypted_private_key(self, encrypted):
        with closing(db.get_connection()) as connection:
            with connection:
                connection.execute(
                    """
                    UPDATE user_keys
                    SET encrypted_private_key = ?
                    WHERE user_id = ?
                    """,
                    (encrypted, self.user_id),
                )

    def _encrypt_test_payload(self, payload):
        kek = _derive_kek(
            self.password,
            self.salt,
        )

        return encrypt_blob(
            payload,
            kek,
            "AES",
            _private_key_context(self.user_id),
        )

    def _assert_key_matches(self, recovered):
        self.assertTrue(recovered.has_private())
        self.assertEqual(recovered.size_in_bits(), 3072)

        self.assertEqual(
            recovered.export_key(format="DER", pkcs=8),
            self.private_key.export_key(
                format="DER",
                pkcs=8,
            ),
        )

    def test_lockout_parameters(self):
        self.assertEqual(
            MAX_FAILED_UNLOCK_ATTEMPTS,
            5,
        )

        self.assertEqual(
            LOCKOUT_DURATION_MINUTES,
            15,
        )

    def test_successful_unlock(self):
        recovered = unlock_private_key(
            self.user_id,
            self.password,
        )

        self._assert_key_matches(recovered)
        self.assertEqual(self._read_state(), (0, None))

    def test_recovered_key_can_unwrap_share_key(self):
        request_id = (
            "550e8400-e29b-41d4-a716-446655440000"
        )

        share_key = bytes(range(32))

        wrapped = wrap_key(
            share_key,
            self.public_key_pem,
            request_id,
        )

        recovered = unlock_private_key(
            self.user_id,
            self.password,
        )

        actual = unwrap_key(
            wrapped,
            recovered,
            request_id,
        )

        self.assertEqual(actual, share_key)

    def test_wrong_password_increments_counter(self):
        with self.assertRaises(KeyUnlockError):
            unlock_private_key(
                self.user_id,
                self.wrong_password,
            )

        self.assertEqual(self._read_state(), (1, None))

    def test_first_four_failures_do_not_lock(self):
        for expected_count in range(1, 5):
            with self.subTest(expected_count=expected_count):
                with self.assertRaises(KeyUnlockError):
                    unlock_private_key(
                        self.user_id,
                        self.wrong_password,
                    )

                self.assertEqual(
                    self._read_state(),
                    (expected_count, None),
                )

    def test_fifth_failure_activates_lockout(self):
        self._set_state(4)

        with self.assertRaises(KeyLockedError):
            unlock_private_key(
                self.user_id,
                self.wrong_password,
            )

        count, locked_until = self._read_state()

        self.assertEqual(count, 5)

        self.assertEqual(
            datetime.fromisoformat(locked_until),
            self.now + timedelta(minutes=15),
        )

    def test_correct_password_rejected_during_lockout(self):
        deadline = (
            self.now + timedelta(minutes=15)
        ).isoformat()

        self._set_state(5, deadline)

        with self.assertRaises(KeyLockedError):
            unlock_private_key(
                self.user_id,
                self.password,
            )

        self.assertEqual(
            self._read_state(),
            (5, deadline),
        )

    def test_locked_attempt_skips_scrypt(self):
        self._set_state(
            5,
            (self.now + timedelta(minutes=15)).isoformat(),
        )

        with patch("user_keys._derive_kek") as mocked_kek:
            with self.assertRaises(KeyLockedError):
                unlock_private_key(
                    self.user_id,
                    self.wrong_password,
                )

            mocked_kek.assert_not_called()

    def test_locked_attempt_does_not_extend_lockout(self):
        deadline = (
            self.now + timedelta(minutes=10)
        ).isoformat()

        self._set_state(5, deadline)

        for _ in range(3):
            with self.assertRaises(KeyLockedError):
                unlock_private_key(
                    self.user_id,
                    self.wrong_password,
                )

        self.assertEqual(
            self._read_state(),
            (5, deadline),
        )

    def test_success_resets_failed_counter(self):
        self._set_state(3)

        recovered = unlock_private_key(
            self.user_id,
            self.password,
        )

        self._assert_key_matches(recovered)
        self.assertEqual(self._read_state(), (0, None))

    def test_expired_lockout_allows_success(self):
        expired = (
            self.now - timedelta(seconds=1)
        ).isoformat()

        self._set_state(5, expired)

        recovered = unlock_private_key(
            self.user_id,
            self.password,
        )

        self._assert_key_matches(recovered)
        self.assertEqual(self._read_state(), (0, None))

    def test_expired_lockout_wrong_password_starts_at_one(self):
        expired = (
            self.now - timedelta(seconds=1)
        ).isoformat()

        self._set_state(5, expired)

        with self.assertRaises(KeyUnlockError):
            unlock_private_key(
                self.user_id,
                self.wrong_password,
            )

        self.assertEqual(self._read_state(), (1, None))

    def test_exact_lockout_expiry_boundary(self):
        self._set_state(
            5,
            self.now.isoformat(),
        )

        recovered = unlock_private_key(
            self.user_id,
            self.password,
        )

        self._assert_key_matches(recovered)
        self.assertEqual(self._read_state(), (0, None))

    def test_sqlite_utc_timestamp_is_supported(self):
        deadline = (
            self.now + timedelta(minutes=10)
        ).strftime("%Y-%m-%d %H:%M:%S")

        self._set_state(5, deadline)

        with self.assertRaises(KeyLockedError):
            unlock_private_key(
                self.user_id,
                self.password,
            )

        self.assertEqual(
            self._read_state(),
            (5, deadline),
        )

    def test_invalid_password_counts_as_failed_attempt(self):
        with patch("user_keys._derive_kek") as mocked_kek:
            for expected_count, password in enumerate(
                ("", None, b"password"),
                start=1,
            ):
                with self.subTest(password=password):
                    with self.assertRaises(KeyUnlockError):
                        unlock_private_key(
                            self.user_id,
                            password,
                        )

                    self.assertEqual(
                        self._read_state(),
                        (expected_count, None),
                    )

            mocked_kek.assert_not_called()

    def test_missing_keypair_rejected_without_scrypt(self):
        with closing(db.get_connection()) as connection:
            with connection:
                connection.execute(
                    """
                    DELETE FROM user_keys
                    WHERE user_id = ?
                    """,
                    (self.user_id,),
                )

        with patch("user_keys._derive_kek") as mocked_kek:
            with self.assertRaises(KeyUnlockError):
                unlock_private_key(
                    self.user_id,
                    self.password,
                )

            mocked_kek.assert_not_called()

    def test_tampered_envelope_increments_counter(self):
        tampered = bytearray(
            self.encrypted_private_key
        )

        tampered[-1] ^= 0x01

        self._replace_encrypted_private_key(
            bytes(tampered)
        )

        with self.assertRaises(KeyUnlockError):
            unlock_private_key(
                self.user_id,
                self.password,
            )

        self.assertEqual(self._read_state(), (1, None))

    def test_invalid_der_is_rejected(self):
        encrypted = self._encrypt_test_payload(
            b"not-an-rsa-private-key"
        )

        self._replace_encrypted_private_key(encrypted)

        with self.assertRaises(KeyUnlockError):
            unlock_private_key(
                self.user_id,
                self.password,
            )

        self.assertEqual(self._read_state(), (1, None))

    def test_public_key_payload_is_rejected(self):
        public_der = (
            self.private_key.public_key()
            .export_key(format="DER")
        )

        encrypted = self._encrypt_test_payload(
            public_der
        )

        self._replace_encrypted_private_key(encrypted)

        with self.assertRaises(KeyUnlockError):
            unlock_private_key(
                self.user_id,
                self.password,
            )

        self.assertEqual(self._read_state(), (1, None))

    def test_operational_failure_does_not_increment_counter(self):
        self._set_state(2)

        with patch(
            "user_keys._derive_kek",
            side_effect=MemoryError("Simulated failure"),
        ):
            with self.assertRaises(MemoryError):
                unlock_private_key(
                    self.user_id,
                    self.password,
                )

        self.assertEqual(self._read_state(), (2, None))

    def test_unlock_does_not_modify_stored_key_material(self):
        before = dict(self._read_row())

        unlock_private_key(
            self.user_id,
            self.password,
        )

        after = dict(self._read_row())

        for field in (
            "public_key_pem",
            "fingerprint",
            "private_key_salt",
            "encrypted_private_key",
            "created_at",
        ):
            with self.subTest(field=field):
                self.assertEqual(
                    before[field],
                    after[field],
                )

    def test_concurrent_failures_do_not_lose_updates(self):
        barrier = Barrier(2)

        def simulated_failure(*args):
            barrier.wait(timeout=10)

            raise KeyUnlockError(
                "Simulated incorrect password."
            )

        def attempt():
            try:
                unlock_private_key(
                    self.user_id,
                    self.wrong_password,
                )
            except KeyUnlockError:
                return "failed"

            return "unexpected"

        with patch(
            "user_keys._recover_private_key",
            side_effect=simulated_failure,
        ):
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [
                    executor.submit(attempt)
                    for _ in range(2)
                ]

                results = [
                    future.result(timeout=20)
                    for future in futures
                ]

        self.assertEqual(results, ["failed", "failed"])
        self.assertEqual(self._read_state(), (2, None))

    def test_concurrent_failures_activate_lockout(self):
        self._set_state(3)

        barrier = Barrier(2)

        def simulated_failure(*args):
            barrier.wait(timeout=10)

            raise KeyUnlockError(
                "Simulated incorrect password."
            )

        def attempt():
            try:
                unlock_private_key(
                    self.user_id,
                    self.wrong_password,
                )

            except KeyLockedError:
                return "locked"

            except KeyUnlockError:
                return "failed"

            return "unexpected"

        with patch(
            "user_keys._recover_private_key",
            side_effect=simulated_failure,
        ):
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [
                    executor.submit(attempt)
                    for _ in range(2)
                ]

                results = [
                    future.result(timeout=20)
                    for future in futures
                ]

        self.assertCountEqual(
            results,
            ["failed", "locked"],
        )

        self.assertEqual(
            self._read_state(),
            (
                5,
                (
                    self.now + timedelta(minutes=15)
                ).isoformat(),
            ),
        )

    def test_inflight_success_cannot_bypass_new_lockout(self):
        self._set_state(4)

        from user_keys import _recover_private_key

        original_recover = _recover_private_key

        def simulate_lockout(*args):
            recovered = original_recover(*args)

            # Another attempt reaches the lockout threshold.
            self._set_state(
                5,
                (
                    self.now + timedelta(minutes=15)
                ).isoformat(),
            )

            return recovered

        with patch(
            "user_keys._recover_private_key",
            side_effect=simulate_lockout,
        ):
            with self.assertRaises(KeyLockedError):
                unlock_private_key(
                    self.user_id,
                    self.password,
                )

        self.assertEqual(
            self._read_state(),
            (
                5,
                (
                    self.now + timedelta(minutes=15)
                ).isoformat(),
            ),
        )


if __name__ == "__main__":
    unittest.main()
