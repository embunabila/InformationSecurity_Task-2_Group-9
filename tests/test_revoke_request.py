import tempfile
import unittest
from pathlib import Path
from unittest.mock import call, patch

import db
from share_access import revoke_request
from share_errors import ShareAccessError


REQUEST_ID = "12345678-1234-5678-1234-567812345678"
STORAGE_NAMES = (
    "a" * 32 + ".bin",
    "b" * 32 + ".bin",
)


class RevokeRequestTests(unittest.TestCase):

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
                            'approved', ?, '2026-11-30 12:00:00')
                    """,
                    (REQUEST_ID, b"dummy-wrapped-key"),
                )

                for index, storage_name in enumerate(STORAGE_NAMES):
                    connection.execute(
                        """
                        INSERT INTO shared_items (
                            id, request_id, category, storage_name
                        )
                        VALUES (?, ?, 'profile', ?)
                        """,
                        (
                            f"item-{index}",
                            REQUEST_ID,
                            storage_name,
                        ),
                    )
        finally:
            connection.close()

    def test_owner_can_revoke_approved_request(self):
        with patch("share_access.delete_envelope") as delete_file:
            revoke_request(1, REQUEST_ID)

        delete_file.assert_has_calls(
            [call(name) for name in STORAGE_NAMES]
        )
        self.assertEqual(delete_file.call_count, 2)

        connection = db.get_connection()
        try:
            request = connection.execute(
                """
                SELECT status, wrapped_key
                FROM share_requests
                WHERE id = ?
                """,
                (REQUEST_ID,),
            ).fetchone()

            items = connection.execute(
                """
                SELECT COUNT(*) AS total
                FROM shared_items
                WHERE request_id = ?
                """,
                (REQUEST_ID,),
            ).fetchone()

            audit = connection.execute(
                """
                SELECT actor_id, action
                FROM share_audit_log
                WHERE request_id = ?
                """,
                (REQUEST_ID,),
            ).fetchone()
        finally:
            connection.close()

        self.assertEqual(request["status"], "revoked")
        self.assertIsNone(request["wrapped_key"])
        self.assertEqual(items["total"], 0)
        self.assertEqual(audit["actor_id"], 1)
        self.assertEqual(audit["action"], "revoked")

    def test_other_user_cannot_revoke_request(self):
        with patch("share_access.delete_envelope") as delete_file:
            with self.assertRaises(ShareAccessError):
                revoke_request(2, REQUEST_ID)

        delete_file.assert_not_called()

    def test_pending_request_cannot_be_revoked(self):
        connection = db.get_connection()
        try:
            connection.execute(
                """
                UPDATE share_requests
                SET status = 'pending',
                    wrapped_key = NULL,
                    expires_at = NULL
                WHERE id = ?
                """,
                (REQUEST_ID,),
            )
            connection.commit()
        finally:
            connection.close()

        with patch("share_access.delete_envelope") as delete_file:
            with self.assertRaises(ShareAccessError):
                revoke_request(1, REQUEST_ID)

        delete_file.assert_not_called()

    def test_storage_error_does_not_update_database(self):
        with patch(
            "share_access.delete_envelope",
            side_effect=OSError("Dummy storage error"),
        ):
            with self.assertRaises(OSError):
                revoke_request(1, REQUEST_ID)

        connection = db.get_connection()
        try:
            request = connection.execute(
                """
                SELECT status, wrapped_key
                FROM share_requests
                WHERE id = ?
                """,
                (REQUEST_ID,),
            ).fetchone()

            items = connection.execute(
                """
                SELECT COUNT(*) AS total
                FROM shared_items
                WHERE request_id = ?
                """,
                (REQUEST_ID,),
            ).fetchone()
        finally:
            connection.close()

        self.assertEqual(request["status"], "approved")
        self.assertEqual(request["wrapped_key"], b"dummy-wrapped-key")
        self.assertEqual(items["total"], 2)


if __name__ == "__main__":
    unittest.main()
