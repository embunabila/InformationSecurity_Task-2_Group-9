
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import db
from share_access import open_shared_item
from share_errors import (
    InvalidKeyPackageError,
    KeyUnlockError,
    ShareAccessError,
)
from share_keys import build_key_package


REQUEST_ID = "12345678-1234-5678-1234-567812345678"
ITEM_ID = "87654321-4321-8765-4321-876543218765"
WRAPPED_KEY = b"w" * 384
FINGERPRINT = " ".join(["ABCD"] * 16)
STORAGE_NAME = "a" * 32 + ".bin"


class OpenSharedItemTests(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.db_patcher = patch.object(
            db,
            "DB_PATH",
            Path(self.temp_dir.name) / "test_medimo.db",
        )
        self.db_patcher.start()
        self.addCleanup(self.db_patcher.stop)

        db.init_db()

        connection = db.get_connection()

        try:
            with connection:
                connection.execute(
                    """
                    INSERT INTO users (id, username, password_hash)
                    VALUES (1, 'owner', 'dummy-hash')
                    """
                )
                connection.execute(
                    """
                    INSERT INTO users (id, username, password_hash)
                    VALUES (2, 'requester', 'dummy-hash')
                    """
                )

                connection.execute(
                    """
                    INSERT INTO share_requests (
                        id, requester_id, owner_id,
                        category, reason, status,
                        wrapped_key, expires_at
                    )
                    VALUES (?, 2, 1, 'profile', 'Test reason',
                            'approved', ?, '2099-12-31 23:59:59')
                    """,
                    (REQUEST_ID, WRAPPED_KEY),
                )

                connection.execute(
                    """
                    INSERT INTO shared_items (
                        id, request_id, category, storage_name
                    )
                    VALUES (?, ?, 'profile', ?)
                    """,
                    (ITEM_ID, REQUEST_ID, STORAGE_NAME),
                )
        finally:
            connection.close()

    def test_requester_can_open_shared_item(self):
        package_text = build_key_package(
            REQUEST_ID,
            WRAPPED_KEY,
            FINGERPRINT,
        )

        expected_metadata = {
            "filename": "profil.json",
            "mime": "application/json",
        }
        expected_bytes = b'{"name":"Test User"}'

        with (
            patch(
                "share_access.get_public_key",
                return_value={"fingerprint": FINGERPRINT},
            ),
            patch(
                "share_access.unlock_private_key",
                return_value="dummy-private-key",
            ),
            patch(
                "share_access.unwrap_key",
                return_value=b"s" * 32,
            ) as unwrap_key,
            patch(
                "share_access._decrypt_shared_envelope",
                return_value=(expected_metadata, expected_bytes),
            ),
        ):
            metadata, file_bytes = open_shared_item(
                2,
                REQUEST_ID,
                ITEM_ID,
                package_text,
                "correct-password",
            )

        self.assertEqual(metadata, expected_metadata)
        self.assertEqual(file_bytes, expected_bytes)

        unwrap_key.assert_called_once_with(
            WRAPPED_KEY,
            "dummy-private-key",
            REQUEST_ID,
        )

        connection = db.get_connection()
        try:
            audit = connection.execute(
                """
                SELECT request_id, actor_id, action
                FROM share_audit_log
                WHERE request_id = ?
                """,
                (REQUEST_ID,),
            ).fetchone()
        finally:
            connection.close()

        self.assertIsNotNone(audit)
        self.assertEqual(audit["request_id"], REQUEST_ID)
        self.assertEqual(audit["actor_id"], 2)
        self.assertEqual(audit["action"], "opened")

    def test_rejects_package_with_wrong_request_id(self):
        wrong_request_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

        package_text = build_key_package(
            wrong_request_id,
            WRAPPED_KEY,
            FINGERPRINT,
        )

        with patch(
            "share_access.get_public_key",
            return_value={"fingerprint": FINGERPRINT},
        ):
            with self.assertRaises(InvalidKeyPackageError):
                open_shared_item(
                    2,
                    REQUEST_ID,
                    ITEM_ID,
                    package_text,
                    "correct-password",
                )

    def test_rejects_package_with_wrong_fingerprint(self):
        wrong_fingerprint = " ".join(["1234"] * 16)

        package_text = build_key_package(
            REQUEST_ID,
            WRAPPED_KEY,
            wrong_fingerprint,
        )

        with patch(
            "share_access.get_public_key",
            return_value={"fingerprint": FINGERPRINT},
        ):
            with self.assertRaises(InvalidKeyPackageError):
                open_shared_item(
                    2,
                    REQUEST_ID,
                    ITEM_ID,
                    package_text,
                    "correct-password",
                )

    def test_rejects_item_from_another_request(self):
        another_item_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

        package_text = build_key_package(
            REQUEST_ID,
            WRAPPED_KEY,
            FINGERPRINT,
        )

        with (
            patch(
                "share_access.get_public_key",
                return_value={"fingerprint": FINGERPRINT},
            ),
            patch(
                "share_access.unlock_private_key",
                return_value="dummy-private-key",
            ),
            patch(
                "share_access.unwrap_key",
                return_value=b"s" * 32,
            ),
        ):
            with self.assertRaises(ShareAccessError):
                open_shared_item(
                    2,
                    REQUEST_ID,
                    another_item_id,
                    package_text,
                    "correct-password",
                )

    def test_rejects_expired_request(self):
        connection = db.get_connection()
        try:
            connection.execute(
                """
                UPDATE share_requests
                SET expires_at = '2000-01-01 00:00:00'
                WHERE id = ?
                """,
                (REQUEST_ID,),
            )
            connection.commit()
        finally:
            connection.close()

        package_text = build_key_package(
            REQUEST_ID,
            WRAPPED_KEY,
            FINGERPRINT,
        )

        with patch("share_access.get_public_key") as get_public_key:
            with self.assertRaises(ShareAccessError):
                open_shared_item(
                    2,
                    REQUEST_ID,
                    ITEM_ID,
                    package_text,
                    "correct-password",
                )

        get_public_key.assert_not_called()

    def test_rejects_wrong_password(self):
        package_text = build_key_package(
            REQUEST_ID,
            WRAPPED_KEY,
            FINGERPRINT,
        )

        with (
            patch(
                "share_access.get_public_key",
                return_value={"fingerprint": FINGERPRINT},
            ),
            patch(
                "share_access.unlock_private_key",
                side_effect=KeyUnlockError("Invalid password"),
            ),
            patch("share_access.unwrap_key") as unwrap_key,
        ):
            with self.assertRaises(KeyUnlockError):
                open_shared_item(
                    2,
                    REQUEST_ID,
                    ITEM_ID,
                    package_text,
                    "wrong-password",
                )

        unwrap_key.assert_not_called()

        connection = db.get_connection()
        try:
            audit_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM share_audit_log
                WHERE request_id = ? AND action = 'opened'
                """,
                (REQUEST_ID,),
            ).fetchone()[0]
        finally:
            connection.close()

        self.assertEqual(audit_count, 0)


if __name__ == "__main__":
    unittest.main()
