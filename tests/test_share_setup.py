import importlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from werkzeug.exceptions import BadRequest


class ShareSetupTests(unittest.TestCase):
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
        self.web_utils = importlib.import_module("web_utils")
        self.app = self.app_module.app

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

        self.config_patcher = patch.dict(self.app.config, {"TESTING": True})
        self.config_patcher.start()
        self.addCleanup(self.config_patcher.stop)

    # --- master key di app.config ---

    def test_master_key_is_stored_in_app_config(self):
        master_key = self.app.config["MASTER_KEY"]
        self.assertIsInstance(master_key, bytes)
        self.assertEqual(len(master_key), 32)
        self.assertIs(master_key, self.app_module.MASTER_KEY)

    # --- current_user_id ---

    def _user_id_with_session(self, value, set_value=True):
        with self.app.test_request_context("/"):
            from flask import session

            if set_value:
                session["user_id"] = value
            return self.web_utils.current_user_id()

    def test_current_user_id_returns_logged_in_id(self):
        self.assertEqual(self._user_id_with_session(7), 7)

    def test_current_user_id_returns_none_without_login(self):
        self.assertIsNone(self._user_id_with_session(None, set_value=False))

    def test_current_user_id_rejects_invalid_values(self):
        for value in (True, False, 0, -1, "7", 7.0, None):
            with self.subTest(value=value):
                self.assertIsNone(self._user_id_with_session(value))

    # --- require_csrf ---

    def _check_csrf(self, session_token, form_token):
        data = {} if form_token is None else {"csrf_token": form_token}

        with self.app.test_request_context("/", method="POST", data=data):
            from flask import session

            if session_token is not None:
                session["csrf_token"] = session_token
            self.web_utils.require_csrf()

    def test_require_csrf_accepts_matching_token(self):
        self._check_csrf("token-benar", "token-benar")

    def test_require_csrf_rejects_wrong_missing_or_absent_token(self):
        cases = (
            ("token-benar", "token-salah"),
            ("token-benar", None),
            ("token-benar", ""),
            (None, "token-apa-saja"),
            (None, ""),
        )
        for session_token, form_token in cases:
            with self.subTest(session=session_token, form=form_token):
                with self.assertRaises(BadRequest):
                    self._check_csrf(session_token, form_token)

    # --- share_errors ---

    def test_share_errors_are_distinct_exceptions(self):
        share_errors = importlib.import_module("share_errors")
        names = (
            "KeyUnlockError",
            "InvalidKeyPackageError",
            "ShareAccessError",
            "KeyLockedError",
        )
        classes = [getattr(share_errors, name) for name in names]

        self.assertEqual(len(set(classes)), 4)
        for cls in classes:
            with self.subTest(cls=cls.__name__):
                self.assertTrue(issubclass(cls, Exception))
                for other in classes:
                    if other is not cls:
                        self.assertFalse(issubclass(cls, other))

    # --- blueprint & menu ---

    def test_sharing_blueprints_are_registered(self):
        for name in ("keys", "requests", "grant", "access"):
            with self.subTest(blueprint=name):
                self.assertIn(name, self.app.blueprints)

    def test_old_routes_still_work_and_menu_has_sharing_links(self):
        connection = self.db_module.get_connection()
        try:
            connection.execute(
                "INSERT INTO users (id, username, password_hash) "
                "VALUES (1, 'dummy_user', 'dummy_hash')"
            )
            connection.commit()
        finally:
            connection.close()

        client = self.app.test_client()
        with client.session_transaction() as session:
            session["user_id"] = 1

        response = client.get("/dashboard")
        self.assertEqual(response.status_code, 200)

        html = response.get_data(as_text=True)
        for href in ('href="/keys"', 'href="/requests"', 'href="/shared"'):
            with self.subTest(href=href):
                self.assertIn(href, html)


if __name__ == "__main__":
    unittest.main()