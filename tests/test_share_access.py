
import unittest
from unittest.mock import patch

from share_access import (
    _validate_key_package,
    _decrypt_shared_envelope,
)
from share_keys import build_key_package
from share_errors import InvalidKeyPackageError


REQUEST_ID = "12345678-1234-5678-1234-567812345678"
OTHER_REQUEST_ID = "87654321-4321-8765-4321-876543218765"

FINGERPRINT = "ABCD " * 15 + "ABCD"
OTHER_FINGERPRINT = "1234 " * 15 + "1234"

WRAPPED_KEY = b"K" * 384


class ShareAccessTests(unittest.TestCase):

    def test_valid_key_package(self):
        package_text = build_key_package(
            REQUEST_ID,
            WRAPPED_KEY,
            FINGERPRINT,
        )

        result = _validate_key_package(
            package_text,
            REQUEST_ID,
            FINGERPRINT,
        )

        self.assertEqual(result, WRAPPED_KEY)

    def test_reject_package_with_different_request_id(self):
        package_text = build_key_package(
            REQUEST_ID,
            WRAPPED_KEY,
            FINGERPRINT,
        )

        with self.assertRaises(InvalidKeyPackageError):
            _validate_key_package(
                package_text,
                OTHER_REQUEST_ID,
                FINGERPRINT,
            )

    def test_reject_package_with_different_fingerprint(self):
        package_text = build_key_package(
            REQUEST_ID,
            WRAPPED_KEY,
            FINGERPRINT,
        )

        with self.assertRaises(InvalidKeyPackageError):
            _validate_key_package(
                package_text,
                REQUEST_ID,
                OTHER_FINGERPRINT,
            )

    def test_reject_malformed_package(self):
        with self.assertRaises(InvalidKeyPackageError):
            _validate_key_package(
                "INVALID-PACKAGE",
                REQUEST_ID,
                FINGERPRINT,
            )

    @patch("share_access.unpack_file_payload")
    @patch("share_access.decrypt_blob")
    @patch("share_access.read_envelope")
    def test_decrypt_shared_envelope(
        self,
        mock_read,
        mock_decrypt,
        mock_unpack,
    ):
        storage_name = "a" * 32 + ".bin"
        share_key = b"S" * 32
        owner_id = 10
        item_id = "12345678-1234-5678-1234-567812345678"

        envelope = b"fake-envelope"
        payload = b"fake-payload"

        expected_metadata = {
            "filename": "report.pdf",
            "mime": "application/pdf",
        }
        expected_file_bytes = b"dummy file content"

        mock_read.return_value = envelope
        mock_decrypt.return_value = payload
        mock_unpack.return_value = (
            expected_metadata,
            expected_file_bytes,
        )

        result = _decrypt_shared_envelope(
            storage_name,
            share_key,
            owner_id,
            item_id,
        )

        self.assertEqual(
            result,
            (expected_metadata, expected_file_bytes),
        )

        mock_read.assert_called_once_with(storage_name)

        mock_decrypt.assert_called_once_with(
            envelope,
            share_key,
            "AES",
            {
                "owner_id": owner_id,
                "kind": "share",
                "item_id": item_id,
            },
        )

        mock_unpack.assert_called_once_with(payload)

    @patch("share_access.unpack_file_payload")
    @patch("share_access.decrypt_blob")
    @patch("share_access.read_envelope")
    def test_invalid_envelope_error_is_propagated(
        self,
        mock_read,
        mock_decrypt,
        mock_unpack,
    ):
        from crypto_core import InvalidEnvelopeError

        mock_read.return_value = b"invalid-envelope"
        mock_decrypt.side_effect = InvalidEnvelopeError(
            "Data tidak dapat diverifikasi."
        )

        with self.assertRaises(InvalidEnvelopeError):
            _decrypt_shared_envelope(
                "a" * 32 + ".bin",
                b"S" * 32,
                10,
                REQUEST_ID,
            )

        mock_unpack.assert_not_called()


if __name__ == "__main__":
    unittest.main()
