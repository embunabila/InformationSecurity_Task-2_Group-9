
import importlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class SharedListTests(unittest.TestCase):

    def setUp(self):
        self.env_patcher = patch.dict(
            os.environ,
            {
                "SECRET_KEY": "dummy-secret-key-for-testing",
                "MASTER_KEY": "11" * 32,
            },
        )
        self.env_patcher.start()
        self.addCleanup(self.env_patcher.stop)

        self.app_module = importlib.import_module("app")
        self.db = importlib.import_module("db")
        self.access_routes = importlib.import_module("access_routes")

        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.db_path_patcher = patch.object(
            self.db,
            "DB_PATH",
            Path(self.temp_dir.name) / "test.db",
        )
        self.db_path_patcher.start()
        self.addCleanup(self.db_path_patcher.stop)

        self.db.init_db()

        self.app = self.app_module.app
        self.app.config.update(TESTING=True)
        self.client = self.app.test_client()

        with self.client.session_transaction() as session:
            session["user_id"] = 1
            session["csrf_token"] = "dummy-csrf-token"

        self.create_test_data()

    def create_test_data(self):
        connection = self.db.get_connection()

        try:
            connection.executemany(
                """
                INSERT INTO users (id, username, password_hash)
                VALUES (?, ?, ?)
                """,
                [
                    (1, "requester", "dummy-hash"),
                    (2, "owner", "dummy-hash"),
                    (3, "another_requester", "dummy-hash"),
                ],
            )

            connection.executemany(
                """
                INSERT INTO share_requests (
                    id,
                    requester_id,
                    owner_id,
                    category,
                    reason,
                    status,
                    expires_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        "request-for-user-1",
                        1,
                        2,
                        "profile",
                        "Profile access",
                        "approved",
                        "2099-12-31 23:59:59",
                    ),
                    (
                        "request-for-user-3",
                        3,
                        2,
                        "video",
                        "Video access",
                        "approved",
                        "2099-12-31 23:59:59",
                    ),
                ],
            )

            connection.executemany(
                """
                INSERT INTO shared_items (
                    id,
                    request_id,
                    category,
                    storage_name
                )
                VALUES (?, ?, ?, ?)
                """,
                [
                    (
                        "item-for-user-1",
                        "request-for-user-1",
                        "profile",
                        "a" * 32 + ".bin",
                    ),
                    (
                        "item-for-user-3",
                        "request-for-user-3",
                        "video",
                        "b" * 32 + ".bin",
                    ),
                ],
            )

            connection.commit()

        finally:
            connection.close()

    def test_redirects_when_user_is_not_logged_in(self):
        client = self.app.test_client()

        response = client.get("/shared")

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_shows_only_items_shared_with_current_user(self):
        with patch.object(
            self.access_routes,
            "expire_old_requests",
        ) as expire_requests:
            response = self.client.get("/shared")

        self.assertEqual(response.status_code, 200)

        page = response.get_data(as_text=True)

        self.assertIn("owner", page)
        self.assertIn("Health Profile", page)

        # Another user's shared item must not appear.
        self.assertNotIn("Medical Video", page)

        expire_requests.assert_called_once()

    def test_shared_page_has_no_store_headers(self):
        with patch.object(
            self.access_routes,
            "expire_old_requests",
        ):
            response = self.client.get("/shared")

        self.assertEqual(
            response.headers["Cache-Control"],
            "no-store",
        )
        self.assertEqual(
            response.headers["X-Content-Type-Options"],
            "nosniff",
        )


if __name__ == "__main__":
    unittest.main()
