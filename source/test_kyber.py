#!/usr/bin/python3

from kyber import KyberPKE, KyberKEM
import math
import numpy as np
from rng import RNG_OS, RNG_AES_CTR

import sys
np.set_printoptions(threshold=sys.maxsize)

def sanity_check():
	for K in [2,3,4]:
		rng = RNG_OS()
		kem = KyberKEM(K, rng)
		for i in range(10):
			public_key, private_key = kem.keygen()
			c, ss1 = kem.encapsulate(public_key)
			ss2 = kem.decapsulate(private_key, c)
			if not np.array_equal(ss1, ss2):
				raise ValueError("Encapsulate() and Decapsulate() returned different shared secrets")
	print("Sanity check passed")

def test_vector_parser(filepath, K, count):
	(N, SYMBYTES, SHARED_SECRET_BYTES) = (256, 32, 32)
	DU = 11 if K == 4 else 10
	DV = 5 if K == 4 else 4
	prefix = ["seed = ", "pk = ", "sk = ", "ct = ", "ss = "]
	length = [len(p) for p in prefix]
	seed = np.zeros((count, 48), dtype=np.uint8)
	pk = np.zeros((count, K*N*12//8 + SYMBYTES), dtype=np.uint8)
	sk = np.zeros((count, K*N*24//8 + 2*SYMBYTES + SHARED_SECRET_BYTES), dtype=np.uint8)
	ct = np.zeros((count, (K*DU + DV)*N//8), dtype=np.uint8)
	ss = np.zeros((count, KyberKEM.SHARED_SECRET_BYTES), dtype=np.uint8)
	r = (seed, pk, sk, ct, ss)
	i = j = 0
	with open(filepath) as f:
		line = f.readline()
		while line and i < count:
			if line.startswith(prefix[j]):
				b = bytes.fromhex(line[length[j]:])
				r[j][i,:] = np.frombuffer(b, dtype=np.uint8)
				if j == len(prefix) - 1:
					j = 0
					i += 1
				else:
					j += 1
			line = f.readline()
	assert i == count
	return r

def test_vector_comparison():
	K = [2, 3, 4]
	dirpath = "test_vectors/"
	filenames = ["kyber512.rsp", "kyber768.rsp", "kyber1024.rsp"]
	count = 100
	for j in range(3):
		(seed, pk, sk, ct, ss) = test_vector_parser(dirpath + filenames[j], K[j], count)
		for i in range(count):
			rng = RNG_AES_CTR(seed[i,:])
			kem = KyberKEM(K[j], rng)
			public_key, private_key = kem.keygen()
			if not np.array_equal(pk[i,:], public_key):
				raise ValueError("Keygen() returned wrong public key")
			if not np.array_equal(sk[i,:], private_key):
				raise ValueError("Keygen() returned wrong private key")
			(c, ss2) = kem.encapsulate(public_key)
			if not np.array_equal(ct[i,:], c):
				raise ValueError("Encapsulate() returned wrong ciphertext")
			if not np.array_equal(ss[i,:], ss2):
				raise ValueError("Encapsulate() returned wrong shared secret")
			ss3 = kem.decapsulate(private_key, c)
			if not np.array_equal(ss[i,:], ss3):
				raise ValueError("Decapsulate() returned wrong shared secret")
	print("Test-vector comparison passed")

def main():
	print("Testing correctness of Kyber...")
	sanity_check()
	test_vector_comparison()

if __name__ == "__main__":
    main()