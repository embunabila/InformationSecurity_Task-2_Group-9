
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import db


class DatabaseSharingTests(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_medimo.db"

        self.db_path_patcher = patch.object(db, "DB_PATH", self.db_path)
        self.db_path_patcher.start()

        db.init_db()

        self.connection = db.get_connection()

        self.connection.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("requester", "hash1")
        )
        self.connection.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("owner", "hash2")
        )
        self.connection.commit()

        self.requester_id = 1
        self.owner_id = 2

    def tearDown(self):
        self.connection.close()
        self.db_path_patcher.stop()
        self.temp_dir.cleanup()

    def create_share_request(self, request_id="request-1"):
        self.connection.execute(
            """
            INSERT INTO share_requests (
                id, requester_id, owner_id, category, expires_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                request_id,
                self.requester_id,
                self.owner_id,
                "document",
                "2026-12-02 08:00:00"
            )
        )
        self.connection.commit()

    def test_all_task2_tables_exist(self):
        tables = {
            row["name"]
            for row in self.connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'table'
                """
            ).fetchall()
        }

        expected_tables = {
            "user_keys",
            "share_requests",
            "shared_items",
            "share_audit_log"
        }

        self.assertTrue(expected_tables.issubset(tables))

    def test_init_db_is_idempotent(self):
        db.init_db()
        db.init_db()

        self.test_all_task2_tables_exist()

    def test_task1_tables_still_exist(self):
        tables = {
            row["name"]
            for row in self.connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'table'
                """
            ).fetchall()
        }

        expected_tables = {
            "users",
            "health_profiles",
            "medical_files"
        }

        self.assertTrue(expected_tables.issubset(tables))

    def test_task1_user_function_still_works(self):
        db.create_user("third_user", "hash3")

        user = db.get_user_by_username("third_user")

        self.assertIsNotNone(user)
        self.assertEqual(user["username"], "third_user")

    def test_user_keys_default_values(self):
        self.connection.execute(
            """
            INSERT INTO user_keys (
                user_id, public_key_pem,
                encrypted_private_key, fingerprint
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                self.owner_id,
                "public-key",
                b"encrypted-private-key",
                "fingerprint-123"
            )
        )
        self.connection.commit()

        result = self.connection.execute(
            "SELECT * FROM user_keys WHERE user_id = ?",
            (self.owner_id,)
        ).fetchone()

        self.assertEqual(result["failed_unlock_count"], 0)
        self.assertIsNone(result["locked_until"])
        self.assertIsNotNone(result["created_at"])
        self.assertIsNotNone(result["updated_at"])

    def test_user_keys_reject_negative_failed_unlock_count(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO user_keys (
                    user_id, public_key_pem,
                    encrypted_private_key, fingerprint,
                    failed_unlock_count
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    self.owner_id,
                    "public-key",
                    b"encrypted-key",
                    "fingerprint-1",
                    -1
                )
            )

    def test_user_keys_fingerprint_must_be_unique(self):
        self.connection.execute(
            """
            INSERT INTO user_keys (
                user_id, public_key_pem,
                encrypted_private_key, fingerprint
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                self.requester_id,
                "public-key-1",
                b"encrypted-1",
                "same-fingerprint"
            )
        )

        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO user_keys (
                    user_id, public_key_pem,
                    encrypted_private_key, fingerprint
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    self.owner_id,
                    "public-key-2",
                    b"encrypted-2",
                    "same-fingerprint"
                )
            )

    def test_share_request_default_status(self):
        self.create_share_request()

        result = self.connection.execute(
            "SELECT status FROM share_requests WHERE id = ?",
            ("request-1",)
        ).fetchone()

        self.assertEqual(result["status"], "pending")

    def test_share_request_rejects_invalid_category(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO share_requests (
                    id, requester_id, owner_id, category, expires_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    "request-invalid",
                    self.requester_id,
                    self.owner_id,
                    "invalid",
                    "2026-12-02 08:00:00"
                )
            )

    def test_share_request_rejects_invalid_status(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO share_requests (
                    id, requester_id, owner_id,
                    category, status, expires_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "request-invalid",
                    self.requester_id,
                    self.owner_id,
                    "document",
                    "invalid",
                    "2026-12-02 08:00:00"
                )
            )

    def test_share_request_rejects_same_requester_and_owner(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO share_requests (
                    id, requester_id, owner_id, category, expires_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    "request-same-user",
                    self.owner_id,
                    self.owner_id,
                    "document",
                    "2026-12-02 08:00:00"
                )
            )

    def test_share_request_rejects_invalid_expires_at_format(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO share_requests (
                    id, requester_id, owner_id, category, expires_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    "request-invalid-date",
                    self.requester_id,
                    self.owner_id,
                    "document",
                    "02-12-2026"
                )
            )

    def test_expires_at_uses_expected_datetime_format(self):
        self.create_share_request()

        result = self.connection.execute(
            "SELECT expires_at FROM share_requests WHERE id = ?",
            ("request-1",)
        ).fetchone()

        self.assertEqual(
            result["expires_at"],
            "2026-12-02 08:00:00"
        )

    def test_shared_item_requires_existing_request(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO shared_items (
                    id, request_id, storage_name
                )
                VALUES (?, ?, ?)
                """,
                ("item-1", "missing-request", "shared-file.enc")
            )

    def test_shared_item_storage_name_must_be_unique(self):
        self.create_share_request()

        self.connection.execute(
            """
            INSERT INTO shared_items (id, request_id, storage_name)
            VALUES (?, ?, ?)
            """,
            ("item-1", "request-1", "shared-file.enc")
        )

        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO shared_items (id, request_id, storage_name)
                VALUES (?, ?, ?)
                """,
                ("item-2", "request-1", "shared-file.enc")
            )

    def test_audit_log_can_be_inserted(self):
        self.create_share_request()

        self.connection.execute(
            """
            INSERT INTO share_audit_log (
                request_id, actor_id, action
            )
            VALUES (?, ?, ?)
            """,
            ("request-1", self.owner_id, "approved")
        )
        self.connection.commit()

        result = self.connection.execute(
            """
            SELECT * FROM share_audit_log
            WHERE request_id = ?
            """,
            ("request-1",)
        ).fetchone()

        self.assertIsNotNone(result)
        self.assertEqual(result["action"], "approved")

    def test_foreign_key_rejects_unknown_user(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO user_keys (
                    user_id, public_key_pem,
                    encrypted_private_key, fingerprint
                )
                VALUES (?, ?, ?, ?)
                """,
                (999, "public-key", b"encrypted-key", "fingerprint-999")
            )

    def test_delete_request_cascades_to_shared_items(self):
        self.create_share_request()

        self.connection.execute(
            """
            INSERT INTO shared_items (id, request_id, storage_name)
            VALUES (?, ?, ?)
            """,
            ("item-1", "request-1", "shared-file.enc")
        )
        self.connection.commit()

        self.connection.execute(
            "DELETE FROM share_requests WHERE id = ?",
            ("request-1",)
        )
        self.connection.commit()

        result = self.connection.execute(
            "SELECT * FROM shared_items WHERE id = ?",
            ("item-1",)
        ).fetchone()

        self.assertIsNone(result)

    def test_delete_user_cascades_to_user_keys(self):
        self.connection.execute(
            """
            INSERT INTO user_keys (
                user_id, public_key_pem,
                encrypted_private_key, fingerprint
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                self.owner_id,
                "public-key",
                b"encrypted-key",
                "fingerprint-delete"
            )
        )
        self.connection.commit()

        self.connection.execute(
            "DELETE FROM users WHERE id = ?",
            (self.owner_id,)
        )
        self.connection.commit()

        result = self.connection.execute(
            "SELECT * FROM user_keys WHERE user_id = ?",
            (self.owner_id,)
        ).fetchone()

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()

