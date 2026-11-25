
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import db
from share_errors import ShareAccessError
from share_requests import (
    create_share_request,
    approve_share_request,
    reject_share_request,
    get_request_for_owner,
    get_active_request_for_requester,
    record_share_event,
)


class ShareRequestsTests(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_medimo.db"

        self.db_path_patcher = patch.object(db, "DB_PATH", self.db_path)
        self.db_path_patcher.start()

        db.init_db()

        connection = db.get_connection()
        connection.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("requester", "hash1"),
        )
        connection.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("owner", "hash2"),
        )
        connection.commit()
        connection.close()

        self.requester_id = 1
        self.owner_id = 2

    def tearDown(self):
        self.db_path_patcher.stop()
        self.temp_dir.cleanup()

    def create_request(self):
        return create_share_request(
            self.requester_id,
            self.owner_id,
            "document",
            "Need it for a check-up",
        )

    def test_create_share_request(self):
        request_id = self.create_request()

        self.assertIsInstance(request_id, str)
        self.assertEqual(len(request_id), 36)

        request = get_request_for_owner(self.owner_id, request_id)

        self.assertEqual(request["requester_id"], self.requester_id)
        self.assertEqual(request["owner_id"], self.owner_id)
        self.assertEqual(request["category"], "document")
        self.assertEqual(request["status"], "pending")
        self.assertIsNone(request["expires_at"])

    def test_create_request_rejects_same_user(self):
        with self.assertRaises(ValueError):
            create_share_request(
                self.requester_id,
                self.requester_id,
                "document",
                "Need it",
            )

    def test_create_request_rejects_invalid_category(self):
        with self.assertRaises(ValueError):
            create_share_request(
                self.requester_id,
                self.owner_id,
                "invalid",
                "Need it",
            )

    def test_create_request_rejects_empty_reason(self):
        for reason in ("", "   "):
            with self.subTest(reason=reason):
                with self.assertRaises(ValueError):
                    create_share_request(
                        self.requester_id,
                        self.owner_id,
                        "document",
                        reason,
                    )

    def test_create_request_rejects_long_reason(self):
        with self.assertRaises(ValueError):
            create_share_request(
                self.requester_id,
                self.owner_id,
                "document",
                "x" * 501,
            )

    def test_create_request_rejects_duplicate_pending_request(self):
        self.create_request()

        with self.assertRaises(sqlite3.IntegrityError):
            self.create_request()

    def test_approve_share_request(self):
        request_id = self.create_request()
        wrapped_key = b"wrapped-test-key"
        expires_at = "2099-12-31 23:59:59"

        result = approve_share_request(
            self.owner_id,
            request_id,
            wrapped_key,
            expires_at,
        )

        self.assertTrue(result)

        request = get_request_for_owner(self.owner_id, request_id)

        self.assertEqual(request["status"], "approved")
        self.assertEqual(bytes(request["wrapped_key"]), wrapped_key)
        self.assertEqual(request["expires_at"], expires_at)
        self.assertIsNotNone(request["decided_at"])

    def test_approve_rejects_empty_wrapped_key(self):
        request_id = self.create_request()

        with self.assertRaises(ValueError):
            approve_share_request(
                self.owner_id,
                request_id,
                b"",
                "2099-12-31 23:59:59",
            )

    def test_approve_rejects_invalid_expiry_format(self):
        request_id = self.create_request()

        with self.assertRaises(ValueError):
            approve_share_request(
                self.owner_id,
                request_id,
                b"wrapped-key",
                "31-12-2099",
            )

    def test_approve_rejects_past_expiry(self):
        request_id = self.create_request()

        with self.assertRaises(ValueError):
            approve_share_request(
                self.owner_id,
                request_id,
                b"wrapped-key",
                "2000-01-01 00:00:00",
            )

    def test_approve_rejects_wrong_owner(self):
        request_id = self.create_request()

        with self.assertRaises(ShareAccessError):
            approve_share_request(
                self.requester_id,
                request_id,
                b"wrapped-key",
                "2099-12-31 23:59:59",
            )

    def test_reject_share_request(self):
        request_id = self.create_request()

        result = reject_share_request(self.owner_id, request_id)

        self.assertTrue(result)

        request = get_request_for_owner(self.owner_id, request_id)

        self.assertEqual(request["status"], "rejected")
        self.assertIsNotNone(request["decided_at"])
        self.assertIsNone(request["expires_at"])

    def test_reject_request_wrong_owner(self):
        request_id = self.create_request()

        with self.assertRaises(ShareAccessError):
            reject_share_request(self.requester_id, request_id)

    def test_get_request_for_owner_rejects_other_owner(self):
        request_id = self.create_request()

        with self.assertRaises(ShareAccessError):
            get_request_for_owner(self.requester_id, request_id)

    def test_get_request_for_owner_rejects_unknown_request(self):
        with self.assertRaises(ShareAccessError):
            get_request_for_owner(self.owner_id, "unknown-request")

    def test_get_active_request_for_requester(self):
        request_id = self.create_request()

        approve_share_request(
            self.owner_id,
            request_id,
            b"wrapped-key",
            "2099-12-31 23:59:59",
        )

        request = get_active_request_for_requester(
            self.requester_id,
            request_id,
        )

        self.assertEqual(request["status"], "approved")
        self.assertEqual(request["owner_id"], self.owner_id)

    def test_active_request_rejects_pending_request(self):
        request_id = self.create_request()

        with self.assertRaises(ShareAccessError):
            get_active_request_for_requester(
                self.requester_id,
                request_id,
            )

    def test_active_request_rejects_expired_request(self):
        request_id = self.create_request()

        connection = db.get_connection()
        connection.execute(
            """
            UPDATE share_requests
            SET status = 'approved',
                wrapped_key = ?,
                expires_at = ?
            WHERE id = ?
            """,
            (b"wrapped-key", "2000-01-01 00:00:00", request_id),
        )
        connection.commit()
        connection.close()

        with self.assertRaises(ShareAccessError):
            get_active_request_for_requester(
                self.requester_id,
                request_id,
            )

    def test_active_request_rejects_wrong_requester(self):
        request_id = self.create_request()

        approve_share_request(
            self.owner_id,
            request_id,
            b"wrapped-key",
            "2099-12-31 23:59:59",
        )

        with self.assertRaises(ShareAccessError):
            get_active_request_for_requester(
                self.owner_id,
                request_id,
            )

    def test_record_share_event(self):
        request_id = self.create_request()

        event_id = record_share_event(
            request_id,
            self.owner_id,
            "approved",
        )

        self.assertIsInstance(event_id, int)

        connection = db.get_connection()
        event = connection.execute(
            """
            SELECT * FROM share_audit_log
            WHERE id = ?
            """,
            (event_id,),
        ).fetchone()
        connection.close()

        self.assertEqual(event["request_id"], request_id)
        self.assertEqual(event["actor_id"], self.owner_id)
        self.assertEqual(event["action"], "approved")

    def test_record_share_event_rejects_empty_action(self):
        with self.assertRaises(ValueError):
            record_share_event(None, self.owner_id, "   ")


if __name__ == "__main__":
    unittest.main()
