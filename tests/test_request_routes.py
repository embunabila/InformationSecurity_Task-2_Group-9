import importlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

OWNER_ID = 1
REQUESTER_ID = 2
STRANGER_ID = 3
FILE_ID = "11111111-1111-4111-8111-111111111111"
PUBLIC_KEY = {"public_key_pem": "dummy-pem", "fingerprint": "dummy-fingerprint"}


class RequestRoutesTests(unittest.TestCase):
    def setUp(self):
        env = patch.dict(
            os.environ,
            {"SECRET_KEY": "dummy-secret-key-for-testing", "MASTER_KEY": "11" * 32},
        )
        env.start()
        self.addCleanup(env.stop)

        self.app_module = importlib.import_module("app")
        self.db = importlib.import_module("db")
        self.share_requests = importlib.import_module("share_requests")

        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        db_path = patch.object(self.db, "DB_PATH", Path(temp_dir.name) / "test.db")
        db_path.start()
        self.addCleanup(db_path.stop)
        self.db.init_db()

        connection = self.db.get_connection()
        try:
            connection.executemany(
                "INSERT INTO users (id, username, password_hash) VALUES (?, ?, 'x')",
                [(OWNER_ID, "owner"), (REQUESTER_ID, "requester"), (STRANGER_ID, "stranger")],
            )
            connection.execute(
                """
                INSERT INTO medical_files (
                    id, owner_id, category,
                    aes_storage_name, des_storage_name, rc4_storage_name
                )
                VALUES (?, ?, 'document', 'a', 'd', 'r')
                """,
                (FILE_ID, OWNER_ID),
            )
            connection.commit()
        finally:
            connection.close()

        # Every user "has" a key pair; real RSA is tested in test_user_keys.
        for target in ("share_requests.get_public_key", "request_routes.get_public_key"):
            patcher = patch(target, return_value=PUBLIC_KEY)
            patcher.start()
            self.addCleanup(patcher.stop)

        config = patch.dict(self.app_module.app.config, {"TESTING": True})
        config.start()
        self.addCleanup(config.stop)

        self.client = self.app_module.app.test_client()

    def _login(self, user_id):
        with self.client.session_transaction() as session:
            session["user_id"] = user_id
            session["csrf_token"] = "test-token"

    def _send(self, owner_username="owner", reason="Need it for a check-up", token="test-token"):
        return self.client.post(
            "/requests",
            data={
                "csrf_token": token,
                "owner_username": owner_username,
                "category": "document",
                "reason": reason,
            },
        )

    def _page(self):
        return self.client.get("/requests").get_data(as_text=True)

    def _status(self, request_id):
        connection = self.db.get_connection()
        try:
            return connection.execute(
                "SELECT status FROM share_requests WHERE id = ?", (request_id,)
            ).fetchone()["status"]
        finally:
            connection.close()

    def _pending_request(self):
        self._login(REQUESTER_ID)
        self._send()
        return self.share_requests.get_incoming_requests(OWNER_ID)[0]["id"]

    def test_requires_login(self):
        for method, url in (
            ("get", "/requests"),
            ("post", "/requests"),
            ("post", f"/requests/{FILE_ID}/approve"),
            ("post", f"/requests/{FILE_ID}/reject"),
        ):
            with self.subTest(method=method, url=url):
                response = getattr(self.client, method)(url)
                self.assertEqual(response.status_code, 302)
                self.assertTrue(response.headers["Location"].endswith("/login"))

    def test_page_is_not_cached(self):
        self._login(REQUESTER_ID)
        response = self.client.get("/requests")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_send_request_redirects_and_shows_message(self):
        self._login(REQUESTER_ID)
        response = self._send()

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/requests"))
        self.assertIn("Your sharing request has been sent.", self._page())
        self.assertEqual(len(self.share_requests.get_outgoing_requests(REQUESTER_ID)), 1)

    def test_unknown_user_and_duplicate_get_the_same_generic_message(self):
        self._login(REQUESTER_ID)
        self._send()

        for owner_username in ("ghost", "owner"):
            with self.subTest(owner_username=owner_username):
                self._send(owner_username=owner_username)
                html = self._page()
                self.assertIn("could not be sent", html)
                self.assertNotIn("not found", html)
                self.assertNotIn("already have a pending", html)

    def test_input_errors_are_shown(self):
        self._login(REQUESTER_ID)
        self._send(reason="x" * 501)
        self.assertIn("Reason cannot exceed 500 characters.", self._page())

    def test_wrong_csrf_is_rejected(self):
        self._login(REQUESTER_ID)
        response = self._send(token="wrong-token")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.share_requests.get_outgoing_requests(REQUESTER_ID), [])

    def test_owner_approves_request(self):
        request_id = self._pending_request()
        fake_share = {
            "wrapped_key": b"w" * 384,
            "shared_items": [
                {
                    "id": "22222222-2222-4222-8222-222222222222",
                    "source_file_id": FILE_ID,
                    "storage_name": "c" * 32 + ".bin",
                }
            ],
        }

        self._login(OWNER_ID)
        with patch("share_requests.create_share", return_value=fake_share):
            response = self.client.post(
                f"/requests/{request_id}/approve",
                data={"csrf_token": "test-token", "days": "7", "file_ids": FILE_ID},
            )

        self.assertEqual(response.status_code, 302)
        self.assertIn("has been approved", self._page())
        self.assertEqual(self._status(request_id), "approved")

    def test_invalid_days_keep_request_pending(self):
        request_id = self._pending_request()

        self._login(OWNER_ID)
        self.client.post(
            f"/requests/{request_id}/approve",
            data={"csrf_token": "test-token", "days": "5", "file_ids": FILE_ID},
        )

        self.assertIn("could not be approved", self._page())
        self.assertEqual(self._status(request_id), "pending")

    def test_other_users_cannot_approve_or_reject(self):
        request_id = self._pending_request()

        for user_id in (REQUESTER_ID, STRANGER_ID):
            for action in ("approve", "reject"):
                with self.subTest(user_id=user_id, action=action):
                    self._login(user_id)
                    self.client.post(
                        f"/requests/{request_id}/{action}",
                        data={"csrf_token": "test-token", "days": "7", "file_ids": FILE_ID},
                    )
                    self.assertIn("Akses tidak tersedia atau sudah berakhir.", self._page())
                    self.assertEqual(self._status(request_id), "pending")

    def test_owner_rejects_request(self):
        request_id = self._pending_request()

        self._login(OWNER_ID)
        response = self.client.post(
            f"/requests/{request_id}/reject", data={"csrf_token": "test-token"}
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn("has been rejected", self._page())
        self.assertEqual(self._status(request_id), "rejected")


if __name__ == "__main__":
    unittest.main()