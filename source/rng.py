import math
import numpy as np
from abc import ABC, abstractmethod
from Crypto.Cipher import AES

class RNG(ABC):
    def __init__(self):
        pass
    @abstractmethod
    def Bytes(self, nb_of_bytes):
        pass

class RNG_OS(RNG):
    def __init__(self):
        pass
    def Bytes(self, nb_of_bytes):
        return np.random.randint(
            0,
            high=256,
            size=nb_of_bytes,
            dtype=np.uint8)

class RNG_AES_CTR(RNG):
    def __init__(self, seed):
        (K, V) = (bytes(32), bytes(16))
        self.cipher = AES.new(
            K,
            AES.MODE_CTR,
            nonce=b'',
            initial_value=V)
        self.cipher.encrypt(bytes(16)) # Increment V
        self.Update(seed = seed)
    def Bytes(self, nb_of_bytes):   
        n = 16* int(math.ceil(nb_of_bytes / 16))
        pt = bytes(n)
        ct = self.cipher.encrypt(pt)
        ct = np.frombuffer(ct[:nb_of_bytes], dtype=np.uint8)
        self.Update()
        return ct
    def Update(self, seed=None):
        if seed is None:
            pt = bytes(3*16)
        else:
            pt = seed.tobytes()
        ct = self.cipher.encrypt(pt)
        (K, V) = (ct[:32], ct[32:])
        self.cipher = AES.new(
            K,
            AES.MODE_CTR,
            nonce=b'',
            initial_value=V)
        self.cipher.encrypt(bytes(16)) # Increment V