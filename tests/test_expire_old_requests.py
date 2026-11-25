
import tempfile
import unittest
from pathlib import Path
from unittest.mock import call, patch

import db
from share_access import expire_old_requests


EXPIRED_ID = "12345678-1234-5678-1234-567812345678"
FUTURE_ID = "87654321-4321-8765-4321-876543218765"
PENDING_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

STORAGE_NAMES = (
    "a" * 32 + ".bin",
    "b" * 32 + ".bin",
)


class ExpireOldRequestsTests(unittest.TestCase):

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
                connection.executemany(
                    """
                    INSERT INTO users (id, username, password_hash)
                    VALUES (?, ?, ?)
                    """,
                    [
                        (1, "owner", "dummy-hash"),
                        (2, "requester", "dummy-hash"),
                    ],
                )

                requests = [
                    (
                        EXPIRED_ID, 2, 1, "profile",
                        "Expired request", "approved",
                        b"expired-key", "2000-01-01 00:00:00",
                    ),
                    (
                        FUTURE_ID, 2, 1, "profile",
                        "Future request", "approved",
                        b"future-key", "2099-01-01 00:00:00",
                    ),
                    (
                        PENDING_ID, 2, 1, "profile",
                        "Pending request", "pending",
                        None, None,
                    ),
                ]

                connection.executemany(
                    """
                    INSERT INTO share_requests (
                        id, requester_id, owner_id,
                        category, reason, status,
                        wrapped_key, expires_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    requests,
                )

                connection.executemany(
                    """
                    INSERT INTO shared_items (
                        id, request_id, category, storage_name
                    )
                    VALUES (?, ?, 'profile', ?)
                    """,
                    [
                        ("expired-item-1", EXPIRED_ID, STORAGE_NAMES[0]),
                        ("expired-item-2", EXPIRED_ID, STORAGE_NAMES[1]),
                        ("future-item", FUTURE_ID, "c" * 32 + ".bin"),
                    ],
                )
        finally:
            connection.close()

    def test_expires_only_approved_requests_past_expiry(self):
        with patch("share_access.delete_envelope") as delete_file:
            result = expire_old_requests()

        self.assertEqual(result, 1)

        delete_file.assert_has_calls(
            [call(name) for name in STORAGE_NAMES]
        )
        self.assertEqual(delete_file.call_count, 2)

        connection = db.get_connection()
        try:
            expired = connection.execute(
                """
                SELECT status, wrapped_key
                FROM share_requests WHERE id = ?
                """,
                (EXPIRED_ID,),
            ).fetchone()

            future = connection.execute(
                """
                SELECT status, wrapped_key
                FROM share_requests WHERE id = ?
                """,
                (FUTURE_ID,),
            ).fetchone()

            pending = connection.execute(
                """
                SELECT status, wrapped_key
                FROM share_requests WHERE id = ?
                """,
                (PENDING_ID,),
            ).fetchone()

            remaining_items = connection.execute(
                """
                SELECT request_id
                FROM shared_items
                ORDER BY request_id
                """
            ).fetchall()

            audit = connection.execute(
                """
                SELECT actor_id, action
                FROM share_audit_log
                WHERE request_id = ?
                """,
                (EXPIRED_ID,),
            ).fetchone()
        finally:
            connection.close()

        self.assertEqual(expired["status"], "expired")
        self.assertIsNone(expired["wrapped_key"])

        self.assertEqual(future["status"], "approved")
        self.assertEqual(future["wrapped_key"], b"future-key")

        self.assertEqual(pending["status"], "pending")
        self.assertIsNone(pending["wrapped_key"])

        self.assertEqual(
            [row["request_id"] for row in remaining_items],
            [FUTURE_ID],
        )

        self.assertIsNone(audit["actor_id"])
        self.assertEqual(audit["action"], "expired")

    def test_returns_zero_when_no_requests_are_expired(self):
        connection = db.get_connection()
        try:
            connection.execute(
                """
                UPDATE share_requests
                SET expires_at = '2099-01-01 00:00:00'
                WHERE id = ?
                """,
                (EXPIRED_ID,),
            )
            connection.commit()
        finally:
            connection.close()

        with patch("share_access.delete_envelope") as delete_file:
            result = expire_old_requests()

        self.assertEqual(result, 0)
        delete_file.assert_not_called()

    def test_storage_error_rolls_back_database_changes(self):
        with patch(
            "share_access.delete_envelope",
            side_effect=OSError("Dummy storage error"),
        ):
            with self.assertRaises(OSError):
                expire_old_requests()

        connection = db.get_connection()
        try:
            request = connection.execute(
                """
                SELECT status, wrapped_key
                FROM share_requests WHERE id = ?
                """,
                (EXPIRED_ID,),
            ).fetchone()

            items = connection.execute(
                """
                SELECT COUNT(*) AS total
                FROM shared_items WHERE request_id = ?
                """,
                (EXPIRED_ID,),
            ).fetchone()

            audit = connection.execute(
                """
                SELECT COUNT(*) AS total
                FROM share_audit_log WHERE request_id = ?
                """,
                (EXPIRED_ID,),
            ).fetchone()
        finally:
            connection.close()

        self.assertEqual(request["status"], "approved")
        self.assertEqual(request["wrapped_key"], b"expired-key")
        self.assertEqual(items["total"], 2)
        self.assertEqual(audit["total"], 0)


if __name__ == "__main__":
    unittest.main()
