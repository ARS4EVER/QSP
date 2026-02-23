import unittest
from unittest.mock import MagicMock
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.app.app_protocol import AppMessage, AppCmd
from src.app.app_router import AppRouter


class TestAppRouter(unittest.TestCase):

    def setUp(self):
        self.peer_addr = ("192.168.1.100", 8888)
        self.test_hash = "abcdef123456"
        
        self.push_msg = AppMessage(
            cmd=AppCmd.SHARE_PUSH,
            file_hash=self.test_hash,
            share_index=1,
            share_data=b"test_share_data"
        )
        self.push_bytes = self.push_msg.pack()

    def test_direct_dispatch(self):
        router = AppRouter()
        
        mock_push_handler = MagicMock()
        router.register_handler(AppCmd.SHARE_PUSH, mock_push_handler)
        
        router.dispatch_network_data(self.peer_addr, self.push_bytes)
        
        mock_push_handler.assert_called_once()
        
        args, kwargs = mock_push_handler.call_args
        called_addr, called_msg = args
        self.assertEqual(called_addr, self.peer_addr)
        self.assertEqual(called_msg.cmd, AppCmd.SHARE_PUSH)
        self.assertEqual(called_msg.share_data, b"test_share_data")

    def test_ui_invoker_dispatch(self):
        invoker_mock = MagicMock()
        
        def mock_root_after(func, *args):
            invoker_mock(func, *args)

        router = AppRouter(ui_invoker=mock_root_after)
        mock_push_handler = MagicMock()
        router.register_handler(AppCmd.SHARE_PUSH, mock_push_handler)
        
        router.dispatch_network_data(self.peer_addr, self.push_bytes)
        
        mock_push_handler.assert_not_called()
        
        invoker_mock.assert_called_once()
        args, kwargs = invoker_mock.call_args
        passed_func, passed_addr, passed_msg = args
        
        self.assertEqual(passed_func, mock_push_handler)
        self.assertEqual(passed_addr, self.peer_addr)
        self.assertEqual(passed_msg.cmd, AppCmd.SHARE_PUSH)

    def test_malformed_data_interception(self):
        router = AppRouter()
        mock_handler = MagicMock()
        router.register_handler(AppCmd.SHARE_PUSH, mock_handler)
        
        router.dispatch_network_data(self.peer_addr, b"garbage data")
        
        mock_handler.assert_not_called()


if __name__ == "__main__":
    unittest.main()
