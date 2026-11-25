import base64
import importlib
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from crypto_core import InvalidEnvelopeError, decrypt_blob, encrypt_blob
from file_payload import pack_file_payload, unpack_file_payload

MASTER_KEY = bytes.fromhex("11" * 32)
REQUESTER_PEM = "-----BEGIN PUBLIC KEY-----\ndummy\n-----END PUBLIC KEY-----\n"
FAKE_WRAPPED_KEY = b"W" * 384
OWNER_ID = 1
OTHER_ID = 2


def _share_context_supported():
    context = {"owner_id": 1, "kind": "share", "item_id": str(uuid.uuid4())}
    try:
        encrypt_blob(b"", bytes(32), "AES", context)
    except ValueError:
        return False
    return True


NEEDS_SHARE_CONTEXT = unittest.skipUnless(
    _share_context_supported(),
    "needs the 'share' context kind in crypto_core",
)


class CreateShareTests(unittest.TestCase):
    def setUp(self):
        env_patcher = patch.dict(
            os.environ,
            {
                "SECRET_KEY": "dummy-secret-key-for-testing",
                "MASTER_KEY": "11" * 32,
            },
        )
        env_patcher.start()
        self.addCleanup(env_patcher.stop)

        # user_keys may not exist yet; share_keys only needs the name to import.
        if importlib.util.find_spec("user_keys") is None:
            stub = types.ModuleType("user_keys")
            stub.wrap_key = None
            modules_patcher = patch.dict(sys.modules, {"user_keys": stub})
            modules_patcher.start()
            self.addCleanup(modules_patcher.stop)

        sys.modules.pop("share_keys", None)
        self.share_keys = importlib.import_module("share_keys")
        self.addCleanup(sys.modules.pop, "share_keys", None)

        self.db = importlib.import_module("db")
        self.storage = importlib.import_module("storage")

        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        self.storage_dir = Path(temp_dir.name) / "storage"

        for module, name, value in (
            (self.db, "DB_PATH", Path(temp_dir.name) / "test.db"),
            (self.storage, "STORAGE_DIR", self.storage_dir),
        ):
            patcher = patch.object(module, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

        self.db.init_db()
        connection = self.db.get_connection()
        try:
            connection.executemany(
                "INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
                [(OWNER_ID, "owner", "x"), (OTHER_ID, "other", "x")],
            )
            connection.commit()
        finally:
            connection.close()

        self.wrap_calls = []

        def fake_wrap_key(share_key, public_key_pem, request_id):
            self.wrap_calls.append((share_key, public_key_pem, request_id))
            return FAKE_WRAPPED_KEY

        wrap_patcher = patch.object(self.share_keys, "wrap_key", fake_wrap_key)
        wrap_patcher.start()
        self.addCleanup(wrap_patcher.stop)

    # --- helpers ---

    def _add_file(self, owner_id, category, filename, data):
        file_id = str(uuid.uuid4())
        payload = pack_file_payload(
            {"filename": filename, "mime": "application/octet-stream"}, data
        )
        context = {"owner_id": owner_id, "kind": "file", "item_id": file_id}
        envelopes = {
            algorithm: encrypt_blob(payload, MASTER_KEY, algorithm, context)
            for algorithm in ("AES", "DES", "RC4")
        }
        names = self.storage.write_envelope_set(envelopes)
        self.db.create_medical_file(
            file_id, owner_id, category, names["AES"], names["DES"], names["RC4"]
        )
        return file_id

    def _add_profile(self, owner_id, profile):
        plaintext = json.dumps(
            profile, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        context = {"owner_id": owner_id, "kind": "profile", "item_id": "profile"}
        self.db.save_health_profile(
            owner_id,
            *(
                encrypt_blob(plaintext, MASTER_KEY, algorithm, context)
                for algorithm in ("AES", "DES", "RC4")
            ),
        )

    def _stored_files(self):
        if not self.storage_dir.exists():
            return set()
        return {path.name for path in self.storage_dir.iterdir()}

    def _create(self, category, selection, request_id=None):
        return self.share_keys.create_share(
            OWNER_ID,
            request_id or str(uuid.uuid4()),
            category,
            selection,
            REQUESTER_PEM,
            MASTER_KEY,
        )

    def _open_copy(self, item, share_key, owner_id=OWNER_ID):
        envelope = self.storage.read_envelope(item["storage_name"])
        context = {"owner_id": owner_id, "kind": "share", "item_id": item["id"]}
        return decrypt_blob(envelope, share_key, "AES", context)

    # --- runs now ---

    def test_rejects_invalid_arguments(self):
        file_id = self._add_file(OWNER_ID, "identity", "ktp.png", b"img")
        request_id = str(uuid.uuid4())
        before = self._stored_files()

        cases = (
            (True, request_id, "identity", {"file_ids": [file_id]}),
            (0, request_id, "identity", {"file_ids": [file_id]}),
            (OWNER_ID, request_id.upper(), "identity", {"file_ids": [file_id]}),
            (OWNER_ID, "not-a-uuid", "identity", {"file_ids": [file_id]}),
            (OWNER_ID, request_id, "unknown", {"file_ids": [file_id]}),
            (OWNER_ID, request_id, "identity", {"profile_fields": ["name"]}),
            (OWNER_ID, request_id, "profile", {"file_ids": [file_id]}),
            (OWNER_ID, request_id, "identity", {"file_ids": []}),
            (OWNER_ID, request_id, "identity", {"file_ids": [file_id, file_id]}),
            (OWNER_ID, request_id, "identity", {"file_ids": ["not-a-uuid"]}),
            (OWNER_ID, request_id, "identity", {"file_ids": file_id}),
            (OWNER_ID, request_id, "identity", {"file_ids": [file_id], "x": []}),
            (OWNER_ID, request_id, "profile", {"profile_fields": [""]}),
        )
        for owner_id, req_id, category, selection in cases:
            with self.subTest(owner=owner_id, req=req_id, cat=category, sel=selection):
                with self.assertRaises(ValueError):
                    self.share_keys.create_share(
                        owner_id, req_id, category, selection,
                        REQUESTER_PEM, MASTER_KEY,
                    )

        self.assertEqual(self.wrap_calls, [])
        self.assertEqual(self._stored_files(), before)

    def test_rejects_file_of_another_owner(self):
        other_file = self._add_file(OTHER_ID, "identity", "ktp.png", b"img")
        before = self._stored_files()

        with self.assertRaises(ValueError):
            self._create("identity", {"file_ids": [other_file]})

        self.assertEqual(self._stored_files(), before)

    def test_rejects_file_from_another_category(self):
        video_id = self._add_file(OWNER_ID, "video", "batuk.mp4", b"vid")

        with self.assertRaises(ValueError):
            self._create("identity", {"file_ids": [video_id]})

    def test_rejects_missing_profile_or_unknown_field(self):
        with self.assertRaises(ValueError):
            self._create("profile", {"profile_fields": ["name"]})

        self._add_profile(OWNER_ID, {"name": "Dummy", "allergies": None})
        with self.assertRaises(ValueError):
            self._create("profile", {"profile_fields": ["name", "password"]})

    def test_wrap_failure_writes_nothing(self):
        file_id = self._add_file(OWNER_ID, "identity", "ktp.png", b"img")
        before = self._stored_files()

        def failing_wrap(*args):
            raise ValueError("bad public key")

        with patch.object(self.share_keys, "wrap_key", failing_wrap):
            with self.assertRaises(ValueError):
                self._create("identity", {"file_ids": [file_id]})

        self.assertEqual(self._stored_files(), before)

    def test_wraps_fresh_32_byte_key_for_requester(self):
        file_id = self._add_file(OWNER_ID, "identity", "ktp.png", b"img")
        request_id = str(uuid.uuid4())

        with patch.object(self.share_keys, "encrypt_blob", return_value=b"env"):
            result = self._create("identity", {"file_ids": [file_id]}, request_id)
            self._create("identity", {"file_ids": [file_id]})

        self.assertEqual(result["wrapped_key"], FAKE_WRAPPED_KEY)
        self.assertEqual(len(self.wrap_calls), 2)

        share_key, pem, wrapped_for = self.wrap_calls[0]
        self.assertIsInstance(share_key, bytes)
        self.assertEqual(len(share_key), 32)
        self.assertEqual(pem, REQUESTER_PEM)
        self.assertEqual(wrapped_for, request_id)
        self.assertNotEqual(self.wrap_calls[0][0], self.wrap_calls[1][0])

    def test_cleans_up_copies_when_a_later_item_fails(self):
        good_file = self._add_file(OWNER_ID, "identity", "ktp.png", b"img")
        other_file = self._add_file(OTHER_ID, "identity", "ktp2.png", b"img")
        before = self._stored_files()

        with patch.object(self.share_keys, "encrypt_blob", return_value=b"env"):
            with self.assertRaises(ValueError):
                self._create("identity", {"file_ids": [good_file, other_file]})

        self.assertEqual(self._stored_files(), before)

    def test_cleans_up_copies_when_writing_fails(self):
        first = self._add_file(OWNER_ID, "document", "lab.pdf", b"pdf1")
        second = self._add_file(OWNER_ID, "document", "resep.pdf", b"pdf2")
        before = self._stored_files()
        real_write = self.storage.write_envelope
        calls = []

        def write_then_fail(name, envelope):
            calls.append(name)
            if len(calls) == 2:
                raise OSError("disk full")
            real_write(name, envelope)

        with patch.object(self.share_keys, "encrypt_blob", return_value=b"env"), \
                patch.object(self.share_keys, "write_envelope", write_then_fail):
            with self.assertRaises(OSError):
                self._create("document", {"file_ids": [first, second]})

        self.assertEqual(self._stored_files(), before)

    # --- needs the 'share' context from crypto_core ---

    @NEEDS_SHARE_CONTEXT
    def test_file_copies_decrypt_to_original_payload(self):
        files = {
            self._add_file(OWNER_ID, "document", "lab.pdf", b"%PDF lab"): (
                "lab.pdf", b"%PDF lab"
            ),
            self._add_file(OWNER_ID, "document", "resep.pdf", bytes(range(256))): (
                "resep.pdf", bytes(range(256))
            ),
        }

        result = self._create("document", {"file_ids": list(files)})
        share_key = self.wrap_calls[0][0]
        items = result["shared_items"]

        self.assertEqual([item["source_file_id"] for item in items], list(files))
        self.assertEqual(len({item["id"] for item in items}), 2)
        self.assertEqual(len({item["storage_name"] for item in items}), 2)

        for item in items:
            with self.subTest(item=item["id"]):
                self.assertEqual(str(uuid.UUID(item["id"])), item["id"])
                metadata, data = unpack_file_payload(self._open_copy(item, share_key))
                filename, original = files[item["source_file_id"]]
                self.assertEqual(metadata["filename"], filename)
                self.assertEqual(data, original)

    @NEEDS_SHARE_CONTEXT
    def test_copy_only_opens_with_share_key_and_its_own_context(self):
        file_id = self._add_file(OWNER_ID, "identity", "ktp.png", b"img")
        item = self._create("identity", {"file_ids": [file_id]})["shared_items"][0]
        share_key = self.wrap_calls[0][0]

        with self.assertRaises(InvalidEnvelopeError):
            self._open_copy(item, MASTER_KEY)
        with self.assertRaises(InvalidEnvelopeError):
            self._open_copy(item, share_key, owner_id=OTHER_ID)
        with self.assertRaises(InvalidEnvelopeError):
            self._open_copy(dict(item, id=str(uuid.uuid4())), share_key)

    @NEEDS_SHARE_CONTEXT
    def test_profile_copy_contains_only_selected_fields(self):
        self._add_profile(
            OWNER_ID,
            {
                "name": "Dummy",
                "birth_date": "2000-01-01",
                "phone": "0812",
                "allergies": "Penisilin",
            },
        )

        result = self._create("profile", {"profile_fields": ["allergies", "name"]})
        items = result["shared_items"]

        self.assertEqual(len(items), 1)
        self.assertIsNone(items[0]["source_file_id"])

        metadata, data = unpack_file_payload(
            self._open_copy(items[0], self.wrap_calls[0][0])
        )
        self.assertEqual(
            metadata, {"filename": "profil.json", "mime": "application/json"}
        )
        self.assertEqual(
            json.loads(data.decode("utf-8")),
            {"name": "Dummy", "allergies": "Penisilin"},
        )


REQUEST_ID = "0b9f3c2e-6d41-4c8a-9e57-2f1a8b3c4d5e"
WRAPPED_KEY = bytes(range(256)) + bytes(range(128))
FINGERPRINT = " ".join(["3F2A", "91C0"] * 8)


def _raw_package(fields):
    """Encode any JSON (dict or raw string) the way a package is encoded."""
    text = fields if isinstance(fields, str) else json.dumps(
        fields, sort_keys=True, separators=(",", ":")
    )
    body = base64.urlsafe_b64encode(text.encode("utf-8")).rstrip(b"=")
    return "MEDIMO-KEY-1:" + body.decode("ascii")


def _valid_fields(**changes):
    fields = {
        "recipient_fp": FINGERPRINT,
        "request_id": REQUEST_ID,
        "v": 1,
        "wrapped_key": base64.b64encode(WRAPPED_KEY).decode("ascii"),
    }
    fields.update(changes)
    return fields


class KeyPackageTests(unittest.TestCase):
    def setUp(self):
        if importlib.util.find_spec("user_keys") is None:
            stub = types.ModuleType("user_keys")
            stub.wrap_key = None
            modules_patcher = patch.dict(sys.modules, {"user_keys": stub})
            modules_patcher.start()
            self.addCleanup(modules_patcher.stop)

        sys.modules.pop("share_keys", None)
        self.share_keys = importlib.import_module("share_keys")
        self.addCleanup(sys.modules.pop, "share_keys", None)

        self.error = importlib.import_module("share_errors").InvalidKeyPackageError

    def _build(self):
        return self.share_keys.build_key_package(REQUEST_ID, WRAPPED_KEY, FINGERPRINT)

    def test_round_trip(self):
        package = self._build()

        self.assertEqual(
            self.share_keys.parse_key_package(package),
            {
                "recipient_fp": FINGERPRINT,
                "request_id": REQUEST_ID,
                "v": 1,
                "wrapped_key": WRAPPED_KEY,
            },
        )

    def test_package_is_plain_ascii_text(self):
        package = self._build()
        body = package[len("MEDIMO-KEY-1:"):]

        self.assertTrue(package.startswith("MEDIMO-KEY-1:"))
        self.assertLessEqual(len(package), 4096)
        self.assertRegex(body, r"\A[A-Za-z0-9_-]+\Z")
        self.assertEqual(package, self._build())

    def test_package_matches_documented_json(self):
        self.assertEqual(self._build(), _raw_package(_valid_fields()))

    def test_parse_ignores_surrounding_whitespace(self):
        result = self.share_keys.parse_key_package("\n  " + self._build() + " \r\n")
        self.assertEqual(result["wrapped_key"], WRAPPED_KEY)

    def test_build_rejects_invalid_arguments(self):
        cases = (
            (REQUEST_ID.upper(), WRAPPED_KEY, FINGERPRINT),
            ("not-a-uuid", WRAPPED_KEY, FINGERPRINT),
            (REQUEST_ID, WRAPPED_KEY[:-1], FINGERPRINT),
            (REQUEST_ID, WRAPPED_KEY + b"x", FINGERPRINT),
            (REQUEST_ID, WRAPPED_KEY.hex(), FINGERPRINT),
            (REQUEST_ID, WRAPPED_KEY, FINGERPRINT.lower()),
            (REQUEST_ID, WRAPPED_KEY, FINGERPRINT.replace(" ", "")),
            (REQUEST_ID, WRAPPED_KEY, FINGERPRINT[:-5]),
            (REQUEST_ID, WRAPPED_KEY, None),
        )
        for request_id, wrapped_key, fingerprint in cases:
            with self.subTest(request_id=request_id, fingerprint=fingerprint):
                with self.assertRaises(ValueError):
                    self.share_keys.build_key_package(
                        request_id, wrapped_key, fingerprint
                    )

    def test_parse_rejects_malformed_text(self):
        package = self._build()
        body = package[len("MEDIMO-KEY-1:"):]

        cases = (
            None,
            package.encode("ascii"),
            "",
            body,
            "MEDIMO-KEY-2:" + body,
            "medimo-key-1:" + body,
            "MEDIMO-KEY-1:",
            package + "=",
            package[:-4] + "+/+/",
            package[:-10],
            package + "A" * 4096,
            "MEDIMO-KEY-1:" + "A" * 50,
            _raw_package("[1, 2, 3]"),
            _raw_package("not json"),
            _raw_package("[" * 2000 + "]" * 2000),
        )
        for text in cases:
            with self.subTest(text=repr(text)[:40]):
                with self.assertRaises(self.error):
                    self.share_keys.parse_key_package(text)

    def test_parse_rejects_bad_fields(self):
        missing = _valid_fields()
        del missing["v"]
        valid_json = json.dumps(_valid_fields(), sort_keys=True, separators=(",", ":"))

        cases = {
            "missing field": missing,
            "extra field": _valid_fields(owner_id=1),
            "version 2": _valid_fields(v=2),
            "version true": _valid_fields(v=True),
            "version string": _valid_fields(v="1"),
            "version float": _valid_fields(v=1.0),
            "uppercase request id": _valid_fields(request_id=REQUEST_ID.upper()),
            "bad request id": _valid_fields(request_id="123"),
            "request id not string": _valid_fields(request_id=123),
            "lowercase fingerprint": _valid_fields(recipient_fp=FINGERPRINT.lower()),
            "short fingerprint": _valid_fields(recipient_fp=FINGERPRINT[:-5]),
            "short wrapped key": _valid_fields(
                wrapped_key=base64.b64encode(WRAPPED_KEY[:-1]).decode("ascii")
            ),
            "wrapped key not base64": _valid_fields(wrapped_key="!" * 512),
            "wrapped key urlsafe": _valid_fields(
                wrapped_key=base64.urlsafe_b64encode(bytes([251]) * 384).decode("ascii")
            ),
            "wrapped key not string": _valid_fields(wrapped_key=384),
            "duplicate field": valid_json[:-1] + ',"v":1}',
            "not canonical": json.dumps(_valid_fields()),
        }
        for name, fields in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(self.error):
                    self.share_keys.parse_key_package(_raw_package(fields))
                    

if __name__ == "__main__":
    unittest.main()