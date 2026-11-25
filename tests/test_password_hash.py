import importlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from werkzeug.security import check_password_hash


DUMMY_PASSWORD = "dummy-password-untuk-tes-123"


class PasswordHashTests(unittest.TestCase):
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
        self.db_module = importlib.import_module("db")

        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.db_path_patcher = patch.object(
            self.db_module,
            "DB_PATH",
            Path(self.temp_dir.name) / "test.db",
        )
        self.db_path_patcher.start()
        self.addCleanup(self.db_path_patcher.stop)

        self.db_module.init_db()

        self.config_patcher = patch.dict(
            self.app_module.app.config,
            {"TESTING": True},
        )
        self.config_patcher.start()
        self.addCleanup(self.config_patcher.stop)

        self.client = self.app_module.app.test_client()

    def _set_csrf(self, token="csrf-token-untuk-tes"):
        with self.client.session_transaction() as session:
            session["csrf_token"] = token
        return token

    def _register(self, username="dummy_user"):
        token = self._set_csrf()
        return self.client.post(
            "/register",
            data={
                "csrf_token": token,
                "username": username,
                "password": DUMMY_PASSWORD,
                "confirm_password": DUMMY_PASSWORD,
            },
        )

    def test_method_constant_matches_contract(self):
        self.assertEqual(
            self.app_module.PASSWORD_HASH_METHOD,
            "scrypt:131072:8:1",
        )

    def test_register_stores_scrypt_hash_with_contract_parameters(self):
        response = self._register()
        self.assertEqual(response.status_code, 302)

        user = self.db_module.get_user_by_username("dummy_user")
        self.assertIsNotNone(user)

        stored_hash = user["password_hash"]
        self.assertTrue(stored_hash.startswith("scrypt:131072:8:1$"))
        self.assertNotIn(DUMMY_PASSWORD, stored_hash)
        self.assertTrue(check_password_hash(stored_hash, DUMMY_PASSWORD))
        self.assertFalse(check_password_hash(stored_hash, "password-yang-salah-123"))

    def test_login_works_with_new_hash(self):
        self._register()

        token = self._set_csrf()
        response = self.client.post(
            "/login",
            data={
                "csrf_token": token,
                "username": "dummy_user",
                "password": DUMMY_PASSWORD,
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/dashboard"))


if __name__ == "__main__":
    unittest.main()