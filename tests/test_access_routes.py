
import importlib
import os
import unittest
from unittest.mock import patch

import sqlite3

from crypto_core import InvalidEnvelopeError
from share_errors import (
    KeyLockedError,
    KeyUnlockError,
    InvalidKeyPackageError,
    ShareAccessError,
)

class AccessRoutesTests(unittest.TestCase):

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
        self.access_routes = importlib.import_module("access_routes")

        self.app = self.app_module.app

        self.config_patcher = patch.dict(
            self.app.config,
            {"TESTING": True},
        )
        self.config_patcher.start()
        self.addCleanup(self.config_patcher.stop)

        self.client = self.app.test_client()

        with self.client.session_transaction() as session:
            session["user_id"] = 1
            session["csrf_token"] = "dummy-csrf-token"

    def make_data(self, **overrides):
        data = {
            "csrf_token": "dummy-csrf-token",
            "package": "dummy-key-package",
            "password": "dummy-password",
            "mode": "download",
        }
        data.update(overrides)
        return data

    def post_shared_item(self, data=None):
        return self.client.post(
            "/shared/request-123/items/item-456",
            data=data or self.make_data(),
        )

    def test_redirects_when_user_is_not_logged_in(self):
        client = self.app.test_client()

        response = client.post(
            "/shared/request-123/items/item-456",
            data=self.make_data(),
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_rejects_invalid_csrf(self):
        data = self.make_data(csrf_token="wrong-token")

        response = self.post_shared_item(data)

        self.assertEqual(response.status_code, 400)

    def test_rejects_empty_package(self):
        data = self.make_data(package="")

        with patch.object(
            self.access_routes,
            "open_shared_item",
        ) as open_item:
            response = self.post_shared_item(data)

        self.assertEqual(response.status_code, 400)
        open_item.assert_not_called()

    def test_rejects_empty_password(self):
        data = self.make_data(password="")

        with patch.object(
            self.access_routes,
            "open_shared_item",
        ) as open_item:
            response = self.post_shared_item(data)

        self.assertEqual(response.status_code, 400)
        open_item.assert_not_called()

    def test_rejects_invalid_mode(self):
        data = self.make_data(mode="preview")

        with patch.object(
            self.access_routes,
            "open_shared_item",
        ) as open_item:
            response = self.post_shared_item(data)

        self.assertEqual(response.status_code, 400)
        open_item.assert_not_called()

    def test_view_mode_returns_pdf_inline(self):
        metadata = {
            "filename": "dummy.pdf",
            "mime": "application/pdf",
        }

        with patch.object(
            self.access_routes,
            "open_shared_item",
            return_value=(metadata, b"dummy PDF content"),
        ) as open_item:
            response = self.post_shared_item(
                self.make_data(mode="view")
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/pdf")
        self.assertIn(
            "inline",
            response.headers["Content-Disposition"],
        )
        self.assertEqual(response.get_data(), b"dummy PDF content")

        self.assertEqual(
            response.headers["Cache-Control"],
            "no-store",
        )
        self.assertEqual(
            response.headers["X-Content-Type-Options"],
            "nosniff",
        )

        open_item.assert_called_once()

    def test_download_mode_returns_attachment(self):
        metadata = {
            "filename": "dummy.txt",
            "mime": "text/plain",
        }

        with patch.object(
            self.access_routes,
            "open_shared_item",
            return_value=(metadata, b"dummy file content"),
        ) as open_item:
            response = self.post_shared_item(
                self.make_data(mode="download")
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "attachment",
            response.headers["Content-Disposition"],
        )
        self.assertIn(
            "dummy.txt",
            response.headers["Content-Disposition"],
        )
        self.assertEqual(response.get_data(), b"dummy file content")

        self.assertEqual(
            response.headers["Cache-Control"],
            "no-store",
        )
        self.assertEqual(
            response.headers["X-Content-Type-Options"],
            "nosniff",
        )

        open_item.assert_called_once()


    def test_key_verification_errors_return_400(self):
        errors = (
            KeyUnlockError,
            InvalidKeyPackageError,
            InvalidEnvelopeError,
        )

        for error in errors:
            with self.subTest(error=error.__name__):
                with patch.object(
                    self.access_routes,
                    "open_shared_item",
                    side_effect=error(),
                ):
                    response = self.post_shared_item()

                self.assertEqual(response.status_code, 400)
                self.assertIn(
                    "Paket kunci atau password tidak dapat diverifikasi.",
                    response.get_data(as_text=True),
                )
                self.assertEqual(
                    response.headers["Cache-Control"],
                    "no-store",
                )

    def test_key_locked_error_returns_429(self):
        with patch.object(
            self.access_routes,
            "open_shared_item",
            side_effect=KeyLockedError(),
        ):
            response = self.post_shared_item()

        self.assertEqual(response.status_code, 429)
        self.assertIn(
            "Terlalu banyak percobaan.",
            response.get_data(as_text=True),
        )

    def test_share_access_error_returns_404(self):
        with patch.object(
            self.access_routes,
            "open_shared_item",
            side_effect=ShareAccessError(),
        ):
            response = self.post_shared_item()

        self.assertEqual(response.status_code, 404)
        self.assertIn(
            "Akses tidak tersedia atau sudah berakhir.",
            response.get_data(as_text=True),
        )

    def test_database_error_returns_503(self):
        with patch.object(
            self.access_routes,
            "open_shared_item",
            side_effect=sqlite3.OperationalError("dummy database error"),
        ):
            response = self.post_shared_item()

        self.assertEqual(response.status_code, 503)

    def test_storage_error_returns_503(self):
        with patch.object(
            self.access_routes,
            "open_shared_item",
            side_effect=OSError("dummy storage error"),
        ):
            response = self.post_shared_item()

        self.assertEqual(response.status_code, 503)

if __name__ == "__main__":
    unittest.main()
