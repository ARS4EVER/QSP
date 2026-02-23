import unittest
import os
import sys
import tempfile

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.crypto_lattice.keygen import KeyGen

class TestKeyGenPhase2(unittest.TestCase):
    
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.pub_path = os.path.join(self.test_dir.name, 'node.pub')
        self.priv_path = os.path.join(self.test_dir.name, 'node.priv')

    def tearDown(self):
        self.test_dir.cleanup()

    def test_standard_keygen_and_storage(self):
        pk, sk = KeyGen.generate_keys()
        
        self.assertIsInstance(pk, bytes)
        self.assertIsInstance(sk, bytes)
        self.assertGreater(len(pk), 0)
        self.assertGreater(len(sk), 0)
        
        KeyGen.save_keys(pk, sk, self.pub_path, self.priv_path)
        
        self.assertTrue(os.path.exists(self.pub_path))
        self.assertTrue(os.path.exists(self.priv_path))
        
        loaded_pk, loaded_sk = KeyGen.load_keys(self.pub_path, self.priv_path)
        
        self.assertEqual(pk, loaded_pk)
        self.assertEqual(sk, loaded_sk)

if __name__ == '__main__':
    unittest.main()
