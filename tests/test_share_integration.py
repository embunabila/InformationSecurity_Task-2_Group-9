"""End-to-end sharing flow with real routes, RSA and scrypt (no mocks)."""

import importlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

CSRF_TOKEN = "integration-test-csrf-token"
OWNER_PASSWORD = "owner-dummy-password-123"
REQUESTER_PASSWORD = "requester-dummy-password-123"
THIRD_PASSWORD = "third-dummy-password-1234"

DOCUMENT_NAME = "hasil-lab-dummy.pdf"
DOCUMENT_BYTES = b"%PDF-1.4\n% dummy lab result\n" + bytes(range(256)) * 4


class ShareIntegrationTests(unittest.TestCase):
    """Builds one approved share once; each test checks a part of the flow."""

    @classmethod
    def setUpClass(cls):
        cls._patchers = []

        cls._start(
            patch.dict(
                os.environ,
                {
                    "SECRET_KEY": "dummy-secret-key-for-testing",
                    "MASTER_KEY": "11" * 32,
                },
            )
        )

        cls.app_module = importlib.import_module("app")
        cls.db = importlib.import_module("db")
        cls.storage = importlib.import_module("storage")
        cls.share_keys = importlib.import_module("share_keys")
        cls.user_keys = importlib.import_module("user_keys")

        cls._temp_dir = tempfile.TemporaryDirectory()
        temp_path = Path(cls._temp_dir.name)
        cls.storage_dir = temp_path / "storage"

        cls._start(patch.object(cls.db, "DB_PATH", temp_path / "test.db"))
        cls._start(patch.object(cls.storage, "STORAGE_DIR", cls.storage_dir))
        cls._start(patch.dict(cls.app_module.app.config, {"TESTING": True}))

        cls.db.init_db()

        try:
            cls._build_shared_document()
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        for patcher in reversed(cls._patchers):
            patcher.stop()
        cls._patchers = []
        cls._temp_dir.cleanup()

    @classmethod
    def _start(cls, patcher):
        patcher.start()
        cls._patchers.append(patcher)

    # --- helpers ---

    @classmethod
    def _client(cls):
        client = cls.app_module.app.test_client()
        with client.session_transaction() as session:
            session["csrf_token"] = CSRF_TOKEN
        return client

    @classmethod
    def _register_and_login(cls, username, password):
        client = cls._client()

        response = client.post(
            "/register",
            data={
                "csrf_token": CSRF_TOKEN,
                "username": username,
                "password": password,
                "confirm_password": password,
            },
        )
        assert response.status_code == 302, response.status_code

        # Registration rotates the CSRF token, so set it again for login.
        with client.session_transaction() as session:
            session["csrf_token"] = CSRF_TOKEN

        response = client.post(
            "/login",
            data={
                "csrf_token": CSRF_TOKEN,
                "username": username,
                "password": password,
            },
        )
        assert response.status_code == 302, response.status_code

        with client.session_transaction() as session:
            session["csrf_token"] = CSRF_TOKEN
            user_id = session["user_id"]

        return client, user_id

    @classmethod
    def _generate_keypair(cls, client, password):
        response = client.post(
            "/keys/generate",
            data={"csrf_token": CSRF_TOKEN, "password": password},
        )
        assert response.status_code == 303, response.status_code

    @classmethod
    def _query(cls, sql, params=()):
        connection = cls.db.get_connection()
        try:
            return connection.execute(sql, params).fetchall()
        finally:
            connection.close()

    @classmethod
    def _send_request(cls):
        """Requester asks for documents; returns the new request id."""
        response = cls.requester.post(
            "/requests",
            data={
                "csrf_token": CSRF_TOKEN,
                "owner_username": "dummy_owner",
                "category": "document",
                "reason": "Second opinion for a dummy lab result.",
            },
        )
        assert response.status_code == 302, response.status_code

        rows = cls._query(
            "SELECT id FROM share_requests "
            "WHERE requester_id = ? AND owner_id = ? AND status = 'pending'",
            (cls.requester_id, cls.owner_id),
        )
        assert len(rows) == 1, rows
        return rows[0]["id"]

    @classmethod
    def _approve(cls, request_id):
        response = cls.owner.post(
            f"/requests/{request_id}/approve",
            data={
                "csrf_token": CSRF_TOKEN,
                "file_ids": [cls.file_id],
                "days": "7",
            },
        )
        assert response.status_code == 302, response.status_code

        status = cls._query(
            "SELECT status FROM share_requests WHERE id = ?", (request_id,)
        )[0]["status"]
        assert status == "approved", status

    @classmethod
    def _download_package(cls, request_id):
        response = cls.owner.get(f"/requests/{request_id}/package/download")
        assert response.status_code == 200, response.status_code
        return response.get_data(as_text=True)

    @classmethod
    def _item_id(cls, request_id):
        rows = cls._query(
            "SELECT id FROM shared_items WHERE request_id = ?", (request_id,)
        )
        assert len(rows) == 1, rows
        return rows[0]["id"]

    @classmethod
    def _share_document(cls):
        """Request, approve and download a package; returns (id, item, package)."""
        request_id = cls._send_request()
        cls._approve(request_id)
        return (
            request_id,
            cls._item_id(request_id),
            cls._download_package(request_id),
        )

    @classmethod
    def _build_shared_document(cls):
        # 1. Two accounts register and log in through the real routes.
        cls.owner, cls.owner_id = cls._register_and_login(
            "dummy_owner", OWNER_PASSWORD
        )
        cls.requester, cls.requester_id = cls._register_and_login(
            "dummy_requester", REQUESTER_PASSWORD
        )

        # 2. Both generate a keypair (RSA-3072 + scrypt).
        cls._generate_keypair(cls.owner, OWNER_PASSWORD)
        cls._generate_keypair(cls.requester, REQUESTER_PASSWORD)

        # 3. The owner uploads one dummy document (Assignment 1 route).
        response = cls.owner.post(
            "/archives/upload",
            data={
                "csrf_token": CSRF_TOKEN,
                "category": "document",
                "file": (io.BytesIO(DOCUMENT_BYTES), DOCUMENT_NAME, "application/pdf"),
            },
            content_type="multipart/form-data",
        )
        assert response.status_code == 201, response.status_code

        cls.file_id = cls._query(
            "SELECT id FROM medical_files WHERE owner_id = ?", (cls.owner_id,)
        )[0]["id"]

        # 4-6. Request, approve for 7 days, download the key package.
        cls.request_id, cls.item_id, cls.package = cls._share_document()

    def _open(self, client, package, password, request_id=None, item_id=None):
        return client.post(
            f"/shared/{request_id or self.request_id}/items/{item_id or self.item_id}",
            data={
                "csrf_token": CSRF_TOKEN,
                "package": package,
                "password": password,
                "mode": "download",
            },
        )

    # --- 7. happy path ---

    def test_requester_opens_document_with_package_and_password(self):
        response = self._open(self.requester, self.package, REQUESTER_PASSWORD)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, DOCUMENT_BYTES)
        self.assertIn(DOCUMENT_NAME, response.headers["Content-Disposition"])
        self.assertIn("attachment", response.headers["Content-Disposition"])
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_package_matches_request_and_requester_fingerprint(self):
        parsed = self.share_keys.parse_key_package(self.package)
        requester_key = self.user_keys.get_public_key(self.requester_id)
        stored_wrapped_key = self._query(
            "SELECT wrapped_key FROM share_requests WHERE id = ?",
            (self.request_id,),
        )[0]["wrapped_key"]

        self.assertEqual(parsed["request_id"], self.request_id)
        self.assertEqual(parsed["recipient_fp"], requester_key["fingerprint"])
        self.assertEqual(parsed["wrapped_key"], stored_wrapped_key)

        # The requester can read the same fingerprint on their own key page.
        keys_page = self.requester.get("/keys").get_data(as_text=True)
        self.assertIn(requester_key["fingerprint"], keys_page)

        # The owner's package page shows it too, for the out-of-band check.
        package_page = self.owner.get(f"/requests/{self.request_id}/package")
        self.assertEqual(package_page.status_code, 200)
        self.assertIn(requester_key["fingerprint"], package_page.get_data(as_text=True))

    def test_share_copy_on_disk_is_encrypted(self):
        storage_name = self._query(
            "SELECT storage_name FROM shared_items WHERE id = ?", (self.item_id,)
        )[0]["storage_name"]
        envelope = (self.storage_dir / storage_name).read_bytes()

        self.assertNotIn(DOCUMENT_BYTES[:32], envelope)
        self.assertNotIn(DOCUMENT_NAME.encode("utf-8"), envelope)

    # --- 8. failures ---

    def test_third_account_is_rejected(self):
        third, _ = self._register_and_login("dummy_third", THIRD_PASSWORD)

        for password in (THIRD_PASSWORD, REQUESTER_PASSWORD):
            with self.subTest(password=password):
                response = self._open(third, self.package, password)
                self.assertEqual(response.status_code, 404)
                self.assertNotEqual(response.data, DOCUMENT_BYTES)

        response = third.get(f"/requests/{self.request_id}/package/download")
        self.assertEqual(response.status_code, 404)

    def test_wrong_password_is_rejected(self):
        response = self._open(self.requester, self.package, "wrong-dummy-password-123")

        self.assertEqual(response.status_code, 400)
        self.assertNotEqual(response.data, DOCUMENT_BYTES)

        # The correct password still works afterwards (counter resets).
        response = self._open(self.requester, self.package, REQUESTER_PASSWORD)
        self.assertEqual(response.data, DOCUMENT_BYTES)

    def test_package_for_another_request_is_rejected(self):
        other_id, other_item, other_package = self._share_document()

        # Package of request B used on request A, and the other way round.
        for request_id, item_id, package in (
            (self.request_id, self.item_id, other_package),
            (other_id, other_item, self.package),
        ):
            with self.subTest(request_id=request_id):
                response = self._open(
                    self.requester, package, REQUESTER_PASSWORD,
                    request_id=request_id, item_id=item_id,
                )
                self.assertEqual(response.status_code, 400)
                self.assertNotEqual(response.data, DOCUMENT_BYTES)

        # An item from one request cannot be opened through another request.
        response = self._open(
            self.requester, self.package, REQUESTER_PASSWORD, item_id=other_item
        )
        self.assertEqual(response.status_code, 404)

        # Each package still works for its own request.
        response = self._open(
            self.requester, other_package, REQUESTER_PASSWORD,
            request_id=other_id, item_id=other_item,
        )
        self.assertEqual(response.data, DOCUMENT_BYTES)

    # --- 9. revoke ---

    def test_revoked_package_is_rejected_and_copy_destroyed(self):
        # A separate share, so revoking it does not affect the other tests.
        request_id, item_id, package = self._share_document()
        storage_name = self._query(
            "SELECT storage_name FROM shared_items WHERE id = ?", (item_id,)
        )[0]["storage_name"]

        response = self._open(
            self.requester, package, REQUESTER_PASSWORD,
            request_id=request_id, item_id=item_id,
        )
        self.assertEqual(response.data, DOCUMENT_BYTES)

        # Only the owner can revoke.
        response = self.requester.post(
            f"/requests/{request_id}/revoke", data={"csrf_token": CSRF_TOKEN}
        )
        self.assertEqual(response.status_code, 404)

        response = self.owner.post(
            f"/requests/{request_id}/revoke", data={"csrf_token": CSRF_TOKEN}
        )
        self.assertEqual(response.status_code, 302)

        response = self._open(
            self.requester, package, REQUESTER_PASSWORD,
            request_id=request_id, item_id=item_id,
        )
        self.assertEqual(response.status_code, 404)
        self.assertNotEqual(response.data, DOCUMENT_BYTES)

        row = self._query(
            "SELECT status, wrapped_key FROM share_requests WHERE id = ?",
            (request_id,),
        )[0]
        self.assertEqual(row["status"], "revoked")
        self.assertIsNone(row["wrapped_key"])
        self.assertFalse((self.storage_dir / storage_name).exists())
        self.assertEqual(
            self._query("SELECT id FROM shared_items WHERE request_id = ?", (request_id,)),
            [],
        )

        # The package page cannot rebuild the package any more.
        response = self.owner.get(f"/requests/{request_id}/package/download")
        self.assertEqual(response.status_code, 404)

        # Revoking one request does not touch the others.
        response = self._open(self.requester, self.package, REQUESTER_PASSWORD)
        self.assertEqual(response.data, DOCUMENT_BYTES)

    # --- audit log ---

    def test_audit_log_records_actions_without_secrets(self):
        self._open(self.requester, self.package, REQUESTER_PASSWORD)

        actions = {
            row["action"]
            for row in self._query(
                "SELECT action FROM share_audit_log WHERE request_id = ?",
                (self.request_id,),
            )
        }
        self.assertTrue({"requested", "approved", "opened"} <= actions)

        dump = "\n".join(
            str(tuple(row)) for row in self._query("SELECT * FROM share_audit_log")
        )
        for secret in (REQUESTER_PASSWORD, OWNER_PASSWORD, DOCUMENT_NAME, self.package):
            self.assertNotIn(secret, dump)


if __name__ == "__main__":
    unittest.main()