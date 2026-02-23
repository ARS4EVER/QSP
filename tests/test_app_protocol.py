import unittest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.app.app_protocol import AppMessage, AppCmd


class TestAppProtocol(unittest.TestCase):

    def setUp(self):
        self.test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.mock_binary_share = b"\x00\xFF\x1A\x2B\x3C\x4D\x5E\x6F"

    def test_share_push_pack_unpack(self):
        original_msg = AppMessage(
            cmd=AppCmd.SHARE_PUSH,
            file_hash=self.test_hash,
            share_index=3,
            share_data=self.mock_binary_share
        )

        raw_bytes = original_msg.pack()
        self.assertTrue(isinstance(raw_bytes, bytes))

        parsed_msg = AppMessage.unpack(raw_bytes)

        self.assertEqual(parsed_msg.cmd, AppCmd.SHARE_PUSH)
        self.assertEqual(parsed_msg.file_hash, self.test_hash)
        self.assertEqual(parsed_msg.share_index, 3)
        self.assertEqual(parsed_msg.share_data, self.mock_binary_share)
        self.assertIsNone(parsed_msg.error_msg)

    def test_pull_req_pack_unpack(self):
        original_msg = AppMessage(
            cmd=AppCmd.PULL_REQ,
            file_hash=self.test_hash
        )
        
        parsed_msg = AppMessage.unpack(original_msg.pack())
        
        self.assertEqual(parsed_msg.cmd, AppCmd.PULL_REQ)
        self.assertEqual(parsed_msg.file_hash, self.test_hash)
        self.assertIsNone(parsed_msg.share_index)
        self.assertIsNone(parsed_msg.share_data)

    def test_error_msg_pack_unpack(self):
        original_msg = AppMessage(
            cmd=AppCmd.ERROR,
            file_hash=self.test_hash,
            error_msg="Target share not found in Vault."
        )
        
        parsed_msg = AppMessage.unpack(original_msg.pack())
        self.assertEqual(parsed_msg.cmd, AppCmd.ERROR)
        self.assertEqual(parsed_msg.error_msg, "Target share not found in Vault.")

    def test_malformed_json_handling(self):
        with self.assertRaises(ValueError):
            AppMessage.unpack(b"just some random garbage bytes")
            
        missing_cmd = b'{"file_hash": "abc"}'
        with self.assertRaises(ValueError):
            AppMessage.unpack(missing_cmd)

        invalid_cmd = b'{"cmd": "HACK_SYSTEM", "file_hash": "abc"}'
        with self.assertRaises(ValueError):
            AppMessage.unpack(invalid_cmd)


if __name__ == "__main__":
    unittest.main()
