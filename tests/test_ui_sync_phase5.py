import unittest
from unittest.mock import MagicMock
import threading
import time
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.app.ui_bridge import UIBridge


class TestUISyncAndThreadSafety(unittest.TestCase):
    def setUp(self):
        self.mock_root = MagicMock()
        
        self.after_queue = []
        def mock_after(delay, func, *args):
            self.after_queue.append((delay, func, args))
        self.mock_root.after.side_effect = mock_after

        self.ui_bridge = UIBridge(self.mock_root)
        
        self.mock_lbl_status = MagicMock()
        self.mock_progress = MagicMock()
        self.mock_btn_backup = MagicMock()
        
        self.ui_bridge.bind_widgets(
            lbl_net_status=self.mock_lbl_status,
            progress_bar=self.mock_progress,
            btn_backup=self.mock_btn_backup,
            btn_recovery=None
        )

    def test_cross_thread_status_update(self):
        def background_task():
            self.ui_bridge.safe_update_net_status("连接成功", "green")
            
        bg_thread = threading.Thread(target=background_task)
        bg_thread.start()
        bg_thread.join()
        
        self.assertEqual(len(self.after_queue), 1)
        delay, queued_func, args = self.after_queue[0]
        self.assertEqual(delay, 0)
        
        self.mock_lbl_status.configure.assert_not_called()
        
        queued_func()
        
        self.mock_lbl_status.configure.assert_called_once_with(text="连接成功", text_color="green")

    def test_cross_thread_progress_update(self):
        def background_task():
            self.ui_bridge.safe_update_progress(2, 5)
            
        bg_thread = threading.Thread(target=background_task)
        bg_thread.start()
        bg_thread.join()
        
        delay, queued_func, args = self.after_queue[0]
        queued_func()
        
        self.mock_progress.set.assert_called_once_with(0.4)

    def test_cross_thread_button_locking(self):
        self.ui_bridge.safe_set_action_buttons_state("disabled")
        
        delay, queued_func, args = self.after_queue[0]
        queued_func()
        
        self.mock_btn_backup.configure.assert_called_once_with(state="disabled")


if __name__ == "__main__":
    unittest.main()
