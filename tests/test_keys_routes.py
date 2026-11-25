
import importlib
import os
import sqlite3
import unittest

from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.parse import urlsplit

from werkzeug.security import generate_password_hash

import db

from share_errors import KeyUnlockError

from user_keys import (
    generate_user_keypair,
    get_public_key,
)


class TestKeysRoutes(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.user_id = 1
        cls.other_user_id = 2

        cls.password = "MedimoDummyPassword123!"
        cls.wrong_password = "WrongDummyPassword123!"

        cls.csrf_token = "dummy-csrf-token-for-testing"

        cls.password_hash = generate_password_hash(
            cls.password,
            method="scrypt:131072:8:1",
        )

    def setUp(self):
        self.env_patch = patch.dict(
            os.environ,
            {
                "SECRET_KEY": "dummy-secret-key-for-testing",
                "MASTER_KEY": "11" * 32,
            },
        )

        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

        self.temp_dir = TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.db_path = (
            Path(self.temp_dir.name) / "test_medimo.db"
        )

        self.db_patch = patch.object(
            db,
            "DB_PATH",
            self.db_path,
        )

        self.db_patch.start()
        self.addCleanup(self.db_patch.stop)

        db.init_db()

        with closing(db.get_connection()) as connection:
            with connection:
                connection.executemany(
                    """
                    INSERT INTO users (
                        id, username, password_hash
                    )
                    VALUES (?, ?, ?)
                    """,
                    [
                        (
                            self.user_id,
                            "dummy_keys_user",
                            self.password_hash,
                        ),
                        (
                            self.other_user_id,
                            "other_keys_user",
                            self.password_hash,
                        ),
                    ],
                )

        self.app_module = importlib.import_module("app")
        self.app = self.app_module.app

        self.config_patch = patch.dict(
            self.app.config,
            {
                "TESTING": True,
                "SECRET_KEY": "dummy-secret-key-for-testing",
            },
        )

        self.config_patch.start()
        self.addCleanup(self.config_patch.stop)

        self.client = self.app.test_client()

    def _login(self, user_id=1, with_csrf=True):
        with self.client.session_transaction() as session:
            session.clear()
            session["user_id"] = user_id

            if with_csrf:
                session["csrf_token"] = self.csrf_token

    def _post_generate(self, password=None, **extra_fields):
        data = {
            "csrf_token": self.csrf_token,
            "password": (
                self.password
                if password is None
                else password
            ),
        }

        data.update(extra_fields)

        return self.client.post(
            "/keys/generate",
            data=data,
            follow_redirects=False,
        )

    def _read_keypair(self, user_id):
        with closing(db.get_connection()) as connection:
            return connection.execute(
                """
                SELECT *
                FROM user_keys
                WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()

    def _keypair_count(self):
        with closing(db.get_connection()) as connection:
            return connection.execute(
                "SELECT COUNT(*) FROM user_keys"
            ).fetchone()[0]

    def _assert_login_redirect(self, response):
        self.assertIn(
            response.status_code,
            (302, 303),
        )

        self.assertEqual(
            urlsplit(response.headers["Location"]).path,
            "/login",
        )

    def test_get_requires_login(self):
        response = self.client.get("/keys")

        self._assert_login_redirect(response)

    def test_post_requires_login(self):
        with patch(
            "user_keys.generate_user_keypair"
        ) as mocked_generate:

            response = self._post_generate()

            self._assert_login_redirect(response)
            mocked_generate.assert_not_called()

        self.assertEqual(self._keypair_count(), 0)

    def test_invalid_session_user_id_is_rejected(self):
        for user_id in (True, 0, -1, "1"):
            with self.subTest(user_id=user_id):
                self._login(user_id)

                response = self.client.get("/keys")

                self._assert_login_redirect(response)

    def test_stale_session_is_rejected(self):
        self._login(999)

        response = self.client.get("/keys")

        self._assert_login_redirect(response)

        with self.client.session_transaction() as session:
            self.assertNotIn("user_id", session)

    def test_stale_session_post_is_rejected(self):
        self._login(999)

        with patch(
            "user_keys.generate_user_keypair"
        ) as mocked_generate:

            response = self._post_generate()

            self._assert_login_redirect(response)
            mocked_generate.assert_not_called()

        self.assertEqual(self._keypair_count(), 0)

    def test_get_without_keypair_shows_generation_form(self):
        self._login()

        response = self.client.get("/keys")
        html = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)

        self.assertIn("No keypair yet", html)
        self.assertIn('id="generate-keypair-form"', html)
        self.assertIn('type="password"', html)
        self.assertIn('name="csrf_token"', html)

        self.assertNotIn('id="copy-fingerprint"', html)
        self.assertEqual(self._keypair_count(), 0)

    def test_get_initializes_missing_csrf_token(self):
        self._login(with_csrf=False)

        response = self.client.get("/keys")

        self.assertEqual(response.status_code, 200)

        with self.client.session_transaction() as session:
            token = session.get("csrf_token")

        self.assertIsInstance(token, str)
        self.assertEqual(len(token), 64)

        self.assertIn(
            f'value="{token}"',
            response.get_data(as_text=True),
        )

    def test_get_with_keypair_shows_fingerprint(self):
        self._login()

        generate_user_keypair(
            self.user_id,
            self.password,
        )

        keypair = get_public_key(self.user_id)

        response = self.client.get("/keys")
        html = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)

        self.assertIn("Your keypair is ready", html)
        self.assertIn(keypair["fingerprint"], html)
        self.assertIn('id="copy-fingerprint"', html)
        self.assertIn("readonly", html)

        self.assertNotIn('id="generate-keypair-form"', html)
        self.assertNotIn("BEGIN PRIVATE KEY", html)
        self.assertNotIn("BEGIN RSA PRIVATE KEY", html)
        self.assertNotIn("BEGIN PUBLIC KEY", html)

    def test_get_does_not_show_other_users_fingerprint(self):
        generate_user_keypair(
            self.other_user_id,
            self.password,
        )

        other_keypair = get_public_key(
            self.other_user_id
        )

        self._login(self.user_id)

        response = self.client.get(
            f"/keys?user_id={self.other_user_id}"
        )

        html = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)

        self.assertIn("No keypair yet", html)

        self.assertNotIn(
            other_keypair["fingerprint"],
            html,
        )

    def test_invalid_csrf_rejects_generation(self):
        self._login()

        with patch(
            "user_keys.generate_user_keypair"
        ) as mocked_generate:

            response = self._post_generate(
                csrf_token="invalid-token"
            )

            self.assertEqual(
                response.status_code,
                400,
            )

            mocked_generate.assert_not_called()

        self.assertEqual(self._keypair_count(), 0)

    def test_missing_csrf_rejects_generation(self):
        with patch(
            "user_keys.generate_user_keypair"
        ) as mocked_generate:

            # Submitted token is missing.
            self._login()

            response = self.client.post(
                "/keys/generate",
                data={"password": self.password},
            )

            self.assertEqual(response.status_code, 400)

            # Session token is missing.
            self._login(with_csrf=False)

            response = self._post_generate()

            self.assertEqual(response.status_code, 400)

            mocked_generate.assert_not_called()

        self.assertEqual(self._keypair_count(), 0)

    def test_empty_password_rejects_generation(self):
        self._login()

        with patch(
            "user_keys.generate_user_keypair"
        ) as mocked_generate:

            response = self._post_generate(password="")

            self.assertEqual(response.status_code, 400)

            self.assertIn(
                "Paket kunci atau password tidak dapat diverifikasi.",
                response.get_data(as_text=True),
            )

            mocked_generate.assert_not_called()

        self.assertEqual(self._keypair_count(), 0)

    def test_wrong_password_returns_safe_error(self):
        self._login()

        response = self._post_generate(
            password=self.wrong_password,
        )

        html = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 400)

        self.assertIn(
            "Paket kunci atau password tidak dapat diverifikasi.",
            html,
        )

        self.assertNotIn(self.wrong_password, html)
        self.assertNotIn("Password verification failed.", html)

        self.assertEqual(self._keypair_count(), 0)

    def test_successful_generation_redirects_and_persists(self):
        self._login()

        response = self._post_generate()

        self.assertEqual(response.status_code, 303)

        self.assertEqual(
            urlsplit(response.headers["Location"]).path,
            "/keys",
        )

        row = self._read_keypair(self.user_id)

        self.assertIsNotNone(row)
        self.assertEqual(self._keypair_count(), 1)

        self.assertEqual(
            row["encrypted_private_key"][:4],
            b"MDMO",
        )

        self.assertEqual(
            len(row["private_key_salt"]),
            16,
        )

        page = self.client.get(
            response.headers["Location"]
        )

        html = page.get_data(as_text=True)

        self.assertEqual(page.status_code, 200)

        self.assertIn(
            "Your keypair has been generated successfully.",
            html,
        )

        self.assertIn(row["fingerprint"], html)
        self.assertNotIn(self.password, html)
        self.assertNotIn('id="generate-keypair-form"', html)

        with self.client.session_transaction() as session:
            self.assertNotIn(
                self.password,
                repr(dict(session)),
            )

        # Refreshing the page must not generate another keypair.
        self.client.get("/keys")

        self.assertEqual(self._keypair_count(), 1)

        self.assertEqual(
            dict(self._read_keypair(self.user_id)),
            dict(row),
        )

    def test_duplicate_keypair_is_rejected(self):
        self._login()

        generate_user_keypair(
            self.user_id,
            self.password,
        )

        before = dict(
            self._read_keypair(self.user_id)
        )

        with patch(
            "user_keys.generate_user_keypair"
        ) as mocked_generate:

            response = self._post_generate()

            self.assertEqual(
                response.status_code,
                409,
            )

            self.assertIn(
                "You already have a keypair.",
                response.get_data(as_text=True),
            )

            mocked_generate.assert_not_called()

        self.assertEqual(self._keypair_count(), 1)

        self.assertEqual(
            dict(self._read_keypair(self.user_id)),
            before,
        )

    def test_duplicate_service_error_is_handled(self):
        self._login()

        dummy_keypair = {
            "public_key_pem": "dummy-public-key",
            "fingerprint": "ABCD " * 15 + "ABCD",
        }

        with patch(
            "user_keys.get_public_key",
            side_effect=[None, dummy_keypair],
        ):
            with patch(
                "user_keys.generate_user_keypair",
                side_effect=ValueError(
                    "User already has a keypair."
                ),
            ):
                response = self._post_generate()

        self.assertEqual(response.status_code, 409)

        self.assertIn(
            "You already have a keypair.",
            response.get_data(as_text=True),
        )

    def test_generation_ignores_forged_user_id(self):
        self._login(self.user_id)

        with patch(
            "user_keys.generate_user_keypair",
            side_effect=KeyUnlockError(
                "Simulated verification failure."
            ),
        ) as mocked_generate:

            response = self._post_generate(
                user_id=str(self.other_user_id),
            )

            mocked_generate.assert_called_once_with(
                self.user_id,
                self.password,
            )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(self._keypair_count(), 0)

    def test_database_errors_are_safe_and_not_cached(self):
        self._login()

        with patch(
            "user_keys.get_public_key",
            side_effect=sqlite3.OperationalError(
                "Simulated internal database failure"
            ),
        ):
            get_response = self.client.get("/keys")

        with patch(
            "user_keys.generate_user_keypair",
            side_effect=sqlite3.OperationalError(
                "Simulated internal database failure"
            ),
        ):
            post_response = self._post_generate()

        for response in (get_response, post_response):
            with self.subTest(status=response.status_code):
                self.assertEqual(
                    response.status_code,
                    503,
                )

                self.assertEqual(
                    response.headers["Cache-Control"],
                    "no-store",
                )

                self.assertNotIn(
                    "Simulated internal database failure",
                    response.get_data(as_text=True),
                )

        self.assertEqual(self._keypair_count(), 0)

        normal_response = self.client.get("/keys")

        self.assertEqual(
            normal_response.headers["Cache-Control"],
            "no-store",
        )


if __name__ == "__main__":
    unittest.main()
