"""
src/config.py
[系统全局配置 - Single Source of Truth]

"""

import os
import sys

if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_DIR = os.path.join(BASE_DIR, "data")
KEYS_DIR = os.path.join(DATA_DIR, "keys")
SHARES_DIR = os.path.join(DATA_DIR, "shares")

class SigParams:
    NAME = "ML-DSA-44"

    PK_SIZE = 1312  
    SIG_SIZE = 2420 

class KEMParams:
    NAME = "ML-KEM-512"
    PK_SIZE = 800   
    CT_SIZE = 768   
    SS_SIZE = 32    

class ThresholdParams:
    n_participants = 5
    t = 3 

class NetworkParams:
    MTU = 1400
    INITIAL_CWND = 1.0
    HANDSHAKE_TIMEOUT = 5.0
    RTO_INITIAL = 0.2  
