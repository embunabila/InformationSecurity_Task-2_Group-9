
import sqlite3
import tempfile
import unittest
import uuid
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
    create_request,
    approve_request,
    reject_request,
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

    # ============================================================
    # HELPER FUNCTIONS
    # ============================================================

    def create_request(self):
        return create_share_request(
            self.requester_id,
            self.owner_id,
            "document",
            "Need it for a check-up",
        )

    def create_new_request(self, category="document"):
        """Create a request using the new username-based API."""
        with patch(
            "share_requests.get_public_key",
            return_value={"public_key_pem": "test-public-key"},
        ):
            return create_request(
                self.requester_id,
                "owner",
                category,
                "Need access for testing",
            )

    # ============================================================
    # LEGACY CREATE REQUEST TESTS
    # ============================================================

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

    # ============================================================
    # LEGACY APPROVE REQUEST TESTS
    # ============================================================

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

    # ============================================================
    # LEGACY REJECT REQUEST TESTS
    # ============================================================

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

    # ============================================================
    # REQUEST ACCESS TESTS
    # ============================================================

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

    # ============================================================
    # AUDIT LOG TESTS
    # ============================================================

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

    # ============================================================
    # NEW CREATE REQUEST TESTS
    # ============================================================

    def test_new_create_request_success(self):
        request_id = self.create_new_request()

        self.assertIsInstance(request_id, str)
        self.assertEqual(len(request_id), 36)

        request = get_request_for_owner(self.owner_id, request_id)

        self.assertEqual(request["requester_id"], self.requester_id)
        self.assertEqual(request["owner_id"], self.owner_id)
        self.assertEqual(request["category"], "document")
        self.assertEqual(request["status"], "pending")

        connection = db.get_connection()
        event = connection.execute(
            """
            SELECT action FROM share_audit_log
            WHERE request_id = ?
            """,
            (request_id,),
        ).fetchone()
        connection.close()

        self.assertEqual(event["action"], "requested")

    def test_new_create_request_rejects_duplicate_pending(self):
        self.create_new_request()

        with self.assertRaises(ValueError):
            self.create_new_request()

    # ============================================================
    # NEW APPROVE REQUEST TESTS
    # ============================================================

    def test_new_approve_request_success(self):
        request_id = self.create_new_request()

        item_id = str(uuid.uuid4())
        storage_name = "test-shared-envelope"

        share_result = {
            "wrapped_key": b"wrapped-test-key",
            "shared_items": [
                {
                    "id": item_id,
                    "source_file_id": None,
                    "storage_name": storage_name,
                }
            ],
        }

        with (
            patch(
                "share_requests.get_public_key",
                return_value={
                    "public_key_pem": "test-public-key"
                },
            ),
            patch(
                "share_requests.create_share",
                return_value=share_result,
            ),
        ):
            approve_request(
                owner_id=self.owner_id,
                request_id=request_id,
                selection={
                    "file_ids": [str(uuid.uuid4())]
                },
                days=7,
                master_key=b"test-master-key",
            )

        request = get_request_for_owner(self.owner_id, request_id)

        self.assertEqual(request["status"], "approved")
        self.assertEqual(
            bytes(request["wrapped_key"]),
            b"wrapped-test-key",
        )
        self.assertIsNotNone(request["expires_at"])
        self.assertIsNotNone(request["decided_at"])

        connection = db.get_connection()

        items = connection.execute(
            """
            SELECT * FROM shared_items
            WHERE request_id = ?
            """,
            (request_id,),
        ).fetchall()

        event = connection.execute(
            """
            SELECT action FROM share_audit_log
            WHERE request_id = ? AND action = 'approved'
            """,
            (request_id,),
        ).fetchone()

        connection.close()

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["id"], item_id)
        self.assertEqual(items[0]["storage_name"], storage_name)
        self.assertEqual(event["action"], "approved")

    def test_new_approve_request_rejects_invalid_days(self):
        request_id = self.create_new_request()

        for days in (0, 2, 14, 31, -1):
            with self.subTest(days=days):
                with self.assertRaises(ValueError):
                    approve_request(
                        owner_id=self.owner_id,
                        request_id=request_id,
                        selection={
                            "file_ids": [str(uuid.uuid4())]
                        },
                        days=days,
                        master_key=b"test-master-key",
                    )

    def test_new_approve_request_rejects_non_pending_request(self):
        request_id = self.create_new_request()

        reject_request(self.owner_id, request_id)

        with self.assertRaises(ShareAccessError):
            approve_request(
                owner_id=self.owner_id,
                request_id=request_id,
                selection={
                    "file_ids": [str(uuid.uuid4())]
                },
                days=7,
                master_key=b"test-master-key",
            )

    def test_new_approve_request_cleans_up_when_database_fails(self):
        request_id = self.create_new_request()

        item_id = str(uuid.uuid4())
        storage_name = "test-envelope-cleanup"

        share_result = {
            "wrapped_key": b"wrapped-test-key",
            "shared_items": [
                {
                    "id": item_id,
                    "source_file_id": None,
                    "storage_name": storage_name,
                }
            ],
        }

        connection = db.get_connection()
        connection.execute(
            """
            CREATE TRIGGER fail_shared_item_insert
            BEFORE INSERT ON shared_items
            BEGIN
                SELECT RAISE(ABORT, 'simulated database failure');
            END;
            """
        )
        connection.commit()
        connection.close()

        with (
            patch(
                "share_requests.get_public_key",
                return_value={
                    "public_key_pem": "test-public-key"
                },
            ),
            patch(
                "share_requests.create_share",
                return_value=share_result,
            ),
            patch("share_requests.delete_envelope") as cleanup,
        ):
            with self.assertRaises(sqlite3.IntegrityError):
                approve_request(
                    owner_id=self.owner_id,
                    request_id=request_id,
                    selection={
                        "file_ids": [str(uuid.uuid4())]
                    },
                    days=7,
                    master_key=b"test-master-key",
                )

        cleanup.assert_called_once_with(storage_name)

        request = get_request_for_owner(self.owner_id, request_id)
        self.assertEqual(request["status"], "pending")

        connection = db.get_connection()
        items = connection.execute(
            """
            SELECT * FROM shared_items
            WHERE request_id = ?
            """,
            (request_id,),
        ).fetchall()
        connection.close()

        self.assertEqual(len(items), 0)

    # ============================================================
    # NEW REJECT REQUEST TESTS
    # ============================================================

    def test_new_reject_request_success(self):
        request_id = self.create_new_request()

        result = reject_request(self.owner_id, request_id)

        self.assertTrue(result)

        request = get_request_for_owner(self.owner_id, request_id)

        self.assertEqual(request["status"], "rejected")
        self.assertIsNotNone(request["decided_at"])

        connection = db.get_connection()
        event = connection.execute(
            """
            SELECT action FROM share_audit_log
            WHERE request_id = ? AND action = 'rejected'
            """,
            (request_id,),
        ).fetchone()
        connection.close()

        self.assertEqual(event["action"], "rejected")


if __name__ == "__main__":
    unittest.main()
