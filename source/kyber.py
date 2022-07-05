import numpy as np
from Crypto.Hash import SHA3_512
from Crypto.Hash import SHA3_256
from Crypto.Hash import SHAKE128
from Crypto.Hash import SHAKE256
from rng import RNG

class KyberPKE:
    N = 256
    Q = 3329
    QINV = np.int32(62209)
    SYMBYTES = 32
    ZETAS = np.array([
        2285, 2571, 2970, 1812, 1493, 1422, 287, 202,
        3158, 622, 1577, 182, 962, 2127, 1855, 1468,
        573, 2004, 264, 383, 2500, 1458, 1727, 3199,
        2648, 1017, 732, 608, 1787, 411, 3124, 1758,
        1223, 652, 2777, 1015, 2036, 1491, 3047, 1785,
        516, 3321, 3009, 2663, 1711, 2167, 126, 1469,
        2476, 3239, 3058, 830, 107, 1908, 3082, 2378,
        2931, 961, 1821, 2604, 448, 2264, 677, 2054,
        2226, 430, 555, 843, 2078, 871, 1550, 105,
        422, 587, 177, 3094, 3038, 2869, 1574, 1653,
        3083, 778, 1159, 3182, 2552, 1483, 2727, 1119,
        1739, 644, 2457, 349, 418, 329, 3173, 3254,
        817, 1097, 603, 610, 1322, 2044, 1864, 384,
        2114, 3193, 1218, 1994, 2455, 220, 2142, 1670,
        2144, 1799, 2051, 794, 1819, 2475, 2459, 478,
        3221, 3021, 996, 991, 958, 1869, 1522, 1628],
        dtype=np.int16)
    ZETASINV = np.array([
        1701, 1807, 1460, 2371, 2338, 2333, 308, 108,
        2851, 870, 854, 1510, 2535, 1278, 1530, 1185,
        1659, 1187, 3109, 874, 1335, 2111, 136, 1215,
        2945, 1465, 1285, 2007, 2719, 2726, 2232, 2512,
        75, 156, 3000, 2911, 2980, 872, 2685, 1590,
        2210, 602, 1846, 777, 147, 2170, 2551, 246,
        1676, 1755, 460, 291, 235, 3152, 2742, 2907,
        3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103,
        1275, 2652, 1065, 2881, 725, 1508, 2368, 398,
        951, 247, 1421, 3222, 2499, 271, 90, 853,
        1860, 3203, 1162, 1618, 666, 320, 8, 2813,
        1544, 282, 1838, 1293, 2314, 552, 2677, 2106,
        1571, 205, 2918, 1542, 2721, 2597, 2312, 681,
        130, 1602, 1871, 829, 2946, 3065, 1325, 2756,
        1861, 1474, 1202, 2367, 3147, 1752, 2707, 171,
        3127, 3042, 1907, 1836, 1517, 359, 758, 1441],
        dtype=np.int16)
    MONTGOMERY_C = np.int16(np.uint64(0x100000000) % Q)
    def __init__(self, K, rng, seed=None):
        if not isinstance(K, int):
            raise TypeError("K must be an integer")
        if K not in [2,3,4]:
            raise ValueError("K must be 2, 3, or 4")
        self.K = K
        self.ETA1 = 3 if self.K == 2 else 2
        self.ETA2 = 2
        self.DU = 11 if self.K == 4 else 10
        self.DV = 5 if self.K == 4 else 4
        self.rng = rng
    def keygen(self, return_internals=False):
        seed = self.rng.Bytes(KyberPKE.SYMBYTES)
        (rho, sigma) = np.split(KyberPKE.G(seed), 2)
        A = self.generate_A(rho)
        s = np.zeros((self.K, KyberPKE.N), dtype=np.int16)
        for i in range(self.K):
            data = KyberPKE.PRF(sigma, np.uint8(i), 64*self.ETA1)
            s[i] = KyberPKE.CBD(data, self.ETA1)
        e = np.zeros((self.K, KyberPKE.N), dtype=np.int16)
        for i in range(self.K):
            data = KyberPKE.PRF(sigma, np.uint8(self.K + i), 64*self.ETA1)
            e[i] = KyberPKE.CBD(data, self.ETA1)
        s_ntt = np.zeros((self.K, KyberPKE.N), dtype=np.int16)
        for i in range(self.K):
            s_ntt[i] = KyberPKE.NTT(s[i])
        t = np.zeros((self.K, KyberPKE.N), dtype=np.int16)
        for i in range(self.K):
            t[i] = KyberPKE.Montgomery_dot(A[i,:,:], s_ntt)
            t[i] = KyberPKE.ToMontgomery(t[i])
            t[i] +=  KyberPKE.NTT(e[i])
        t %= KyberPKE.Q
        public_key = np.concatenate((KyberPKE.encode(t.ravel(), 12), rho))
        private_key = KyberPKE.encode(s_ntt.ravel(), 12)
        return [public_key, private_key, s, e] if return_internals else \
                [public_key, private_key]
    def encrypt(self, public_key, message, coins, return_internals=False,
                roulette_index = None):
        (t, rho) = np.split(public_key, [self.K*KyberPKE.N*3//2])
        t = np.reshape(KyberPKE.decode(t, 12,
                self.K*KyberPKE.N), (self.K, -1))
        A_trans = self.generate_A(rho, transpose = True)
        r = np.zeros((self.K, KyberPKE.N), dtype=np.int16)
        for i in range(self.K):
            data = KyberPKE.PRF(coins, np.uint8(i), 64*self.ETA1)
            r[i] = KyberPKE.CBD(data, self.ETA1)
        e1 = np.zeros((self.K, KyberPKE.N), dtype=np.int16)
        for i in range(self.K):
            data = KyberPKE.PRF(coins, np.uint8(self.K + i), 64*self.ETA2)
            e1[i] = KyberPKE.CBD(data, self.ETA2)
        data = KyberPKE.PRF(coins, np.uint8(2*self.K), 64*self.ETA2)
        e2 = KyberPKE.CBD(data, self.ETA2)
        r_ntt = np.zeros((self.K, KyberPKE.N), dtype=np.int16)
        for i in range(self.K):
            r_ntt[i] = KyberPKE.NTT(r[i])
        u = np.copy(e1)
        for i in range(self.K):
            u[i] += KyberPKE.INTT(KyberPKE.Montgomery_dot(A_trans[i], r_ntt))
        v = KyberPKE.INTT(KyberPKE.Montgomery_dot(t, r_ntt))
        message = np.unpackbits(message, bitorder='little')
        v += e2 + KyberPKE.decompress(message, 1)
        (u, v) = (u % KyberPKE.Q, v % KyberPKE.Q)
        u2 = KyberPKE.compress(u, self.DU)
        v2 = KyberPKE.compress(v, self.DV)
        if return_internals:
            du = KyberPKE.mod_centered(KyberPKE.decompress(u2, self.DU) - u)
            dv = KyberPKE.mod_centered(KyberPKE.decompress(v2, self.DV) - v)
        if roulette_index is not None:
            v2[roulette_index] = (v2[roulette_index] + 2**(self.DV - 2)) \
                    % (2**(self.DV))
        u = KyberPKE.encode(u2.ravel(), self.DU)
        v = KyberPKE.encode(v2, self.DV)
        c = np.concatenate((u, v))
        return [c, r, e1, du, e2, dv] if return_internals else [c]
    def decrypt(self, private_key, c):
        (u, v) = np.split(c, [self.K*KyberPKE.N*self.DU//8])
        u = KyberPKE.decode(u, self.DU, self.K*KyberPKE.N)
        v = KyberPKE.decode(v, self.DV, KyberPKE.N)
        u = KyberPKE.decompress(u, self.DU)
        u = u.reshape((self.K,-1))
        v = KyberPKE.decompress(v, self.DV)
        for i in range(self.K):
            u[i] = KyberPKE.NTT(u[i])
        s = KyberPKE.decode(private_key, 12, self.K*KyberPKE.N)
        s = s.reshape((self.K, -1))
        m = v - KyberPKE.INTT(KyberPKE.Montgomery_dot(s, u))
        m = KyberPKE.compress(m % KyberPKE.Q, 1)
        m = np.packbits(m, bitorder='little')
        return m
    def generate_A(self, rho, transpose=False):
        A = np.zeros((self.K, self.K, KyberPKE.N), dtype=np.uint16)
        for i in range(self.K):
            for j in range(self.K):
                ind = [i,j] if transpose else [j, i]
                seed = np.concatenate((rho, np.array(ind, dtype=np.uint8)))
                A[i,j,:] = KyberPKE.parse(KyberPKE.XOF(seed, KyberPKE.N*3))
        return A
    @staticmethod
    def mod_centered(x):
        c = np.int16(KyberPKE.Q//2)
        return ((x.astype(np.int16) + c) % KyberPKE.Q) - c
    @staticmethod
    def G(data):
        sha3 = SHA3_512.new()
        sha3.update(data.tobytes())
        return np.frombuffer(sha3.digest(), dtype=np.uint8)
    @staticmethod
    def XOF(data, nb_of_bytes):
        shake = SHAKE128.new()
        shake.update(data.tobytes())
        return np.frombuffer(shake.read(nb_of_bytes), dtype=np.uint8)
    @staticmethod
    def parse(data):
        L = len(data)
        d = KyberPKE.decode(data, 12, L*2//3)
        d_is_valid = d < KyberPKE.Q
        ind = np.searchsorted(np.cumsum(d_is_valid), KyberPKE.N)
        if ind == L:
            raise Error("Insufficient number of valid indices")
        d_is_valid[ind+1:] = False
        return d[d_is_valid]
    @staticmethod
    def PRF(s, b, nb_of_bytes):
        shake = SHAKE256.new()
        shake.update(s.tobytes() + b.tobytes())
        return np.frombuffer(shake.read(nb_of_bytes), dtype=np.uint8)
    @staticmethod
    def CBD(data, eta):
        L = 64*eta
        if len(data) != L:
            raise TypeError("Invalid length")
        bits = np.unpackbits(data, bitorder='little')
        bits = np.reshape(bits, (KyberPKE.N, 2, eta))
        bits = np.sum(bits.astype(np.int8), axis=2)
        return bits[:,0] - bits[:,1]
    @staticmethod
    def CooleyTukeyButterflies(a, b, zeta):
        p = KyberPKE.Montgomery_multiply(b, zeta)
        return (a + p, a - p)
    @staticmethod
    def GentlemanSandeButterflies(a, b, zeta):
        return ((a + b) % KyberPKE.Q, KyberPKE.Montgomery_multiply(a-b, zeta))
    @staticmethod
    def NTT(data):
        data = data.astype(np.int16)
        L = [128, 64, 32, 16, 8, 4, 2]
        for i in range(7):
            ind_a = np.tile(np.arange(L[i]), 2**i) \
                    + np.repeat(np.arange(256,step=2*L[i]), L[i])
            ind_b = ind_a + L[i]
            ind_z = np.repeat(np.arange(2**i, 2**(i+1)), L[i])
            (data[ind_a], data[ind_b]) = KyberPKE.CooleyTukeyButterflies(
                    data[ind_a], data[ind_b], KyberPKE.ZETAS[ind_z])
        return data % KyberPKE.Q
    @staticmethod
    def INTT(data):
        data = data.astype(np.int16)
        L = [128, 64, 32, 16, 8, 4, 2]
        j = 0
        for i in np.flip(np.arange(7)):
            ind_a = np.tile(np.arange(L[i]), 2**i) \
                    + np.repeat(np.arange(256,step=2*L[i]), L[i])
            ind_b = ind_a + L[i]
            ind_z = np.repeat(np.arange(j, j + 2**i), L[i])
            (data[ind_a], data[ind_b]) = KyberPKE.GentlemanSandeButterflies(
                    data[ind_a], data[ind_b], KyberPKE.ZETASINV[ind_z])
            j += 2**i
        return KyberPKE.Montgomery_multiply(data,
                np.repeat(KyberPKE.ZETASINV[127], 256))
    @staticmethod
    def round_half_up(x):
        d = np.floor(x).astype(np.int16)
        return d + (x - d >= 0.5)
    @staticmethod
    def compress(x, delta):
        f = (2**delta)/KyberPKE.Q
        return KyberPKE.round_half_up(f*x) % (2**delta)
    @staticmethod
    def decompress(x, delta):
        f = KyberPKE.Q/(2**delta)
        return KyberPKE.round_half_up(f*x)
    @staticmethod
    def Montgomery_reduce(a):
        x = a.astype(np.int32)
        u = (x * KyberPKE.QINV).astype(np.int16)
        t = np.int32(u) * np.int32(KyberPKE.Q)
        t = x - t
        t >>= 16
        return t.astype(np.int16)
    @staticmethod
    def Montgomery_multiply(a, b):
        c = np.multiply(a.astype(np.int32), b.astype(np.int32))
        return KyberPKE.Montgomery_reduce(c)
    @staticmethod
    def ToMontgomery(a):
        return KyberPKE.Montgomery_multiply(a, KyberPKE.MONTGOMERY_C)
    @staticmethod
    def Montgomery_basecase_multiply(a, b):
        r = np.zeros((256), dtype=np.int16)
        r[0::2] = KyberPKE.Montgomery_multiply(a[1::2], b[1::2])
        r[0::4] = KyberPKE.Montgomery_multiply(r[0::4], KyberPKE.ZETAS[64:])
        r[2::4] = KyberPKE.Montgomery_multiply(r[2::4], -KyberPKE.ZETAS[64:])
        r[0::2] += KyberPKE.Montgomery_multiply(a[0::2], b[0::2])
        r[1::2] = KyberPKE.Montgomery_multiply(a[0::2], b[1::2])
        r[1::2] += KyberPKE.Montgomery_multiply(a[1::2], b[0::2])
        return r % KyberPKE.Q
    @staticmethod
    def Montgomery_dot(a, b):
        c = KyberPKE.Montgomery_basecase_multiply(a[0], b[0])
        for i in range(1, a.shape[0]):
            c += KyberPKE.Montgomery_basecase_multiply(a[i], b[i])
        return c % KyberPKE.Q
    @staticmethod
    def encode(a, nb_of_bits):
        r = np.zeros(len(a)*2, dtype=np.uint8)
        r[0::2] = np.bitwise_and(a, 0xff).astype(np.uint8)
        r[1::2] = np.bitwise_and(a >> 8, 0xff).astype(np.uint8)
        r = np.unpackbits(r, bitorder='little')
        r = r.reshape((-1, 16))
        r = r[:,:nb_of_bits].ravel()
        return np.packbits(r, bitorder='little')
    @staticmethod
    def decode(a, nb_of_bits, nb_of_symbols):
        r = np.unpackbits(a, bitorder='little')
        r = r[:nb_of_symbols*nb_of_bits]
        r = r.reshape((nb_of_symbols, nb_of_bits))
        r = np.pad(r, ((0, 0), (0, 16-nb_of_bits)), 
            mode='constant', constant_values=(0))
        r = np.packbits(r.ravel(), bitorder='little')
        r = r.astype(np.uint16)
        return np.bitwise_or(r[0::2], r[1::2] << 8)

class KyberKEM:
    SHARED_SECRET_BYTES = 32
    def __init__(self, K, rng):
        self.pke = KyberPKE(K, rng)
    def keygen(self, return_internals=False):
        public_key, private_key, *internals = self.pke.keygen(
                return_internals=return_internals)
        h = KyberKEM.H(public_key)
        z = self.pke.rng.Bytes(KyberKEM.SHARED_SECRET_BYTES)
        private_key = np.concatenate((private_key, public_key, h, z))
        return public_key, private_key, *internals
    def encapsulate(self, public_key, return_internals=False):
        m = self.pke.rng.Bytes(KyberPKE.SYMBYTES)
        m = KyberKEM.H(m)
        h = KyberKEM.H(public_key)
        (k, r) = np.split(KyberPKE.G(np.concatenate((m, h))), 2)
        c, *internals = self.pke.encrypt(public_key, m, r, 
                return_internals=return_internals)
        k2 = np.concatenate((k, KyberKEM.H(c)))
        k2 = KyberKEM.KDF(k2)
        return [c, k2, m, *internals, k] if return_internals else [c, k2]
    def decapsulate(self, private_key, c, return_internals=False,
                roulette_index = None):
        l = 12*self.pke.K*KyberPKE.N//8
        sk, pk, h, z = np.split(private_key, [l, 2*l+32, 2*l+64])
        m = self.pke.decrypt(sk, c)
        (k, r) = np.split(KyberPKE.G(np.concatenate((m, h))), 2)
        [c2] = self.pke.encrypt(pk, m, r, roulette_index=roulette_index)
        if not np.array_equal(c, c2):
            k = z
        k = np.concatenate((k, KyberKEM.H(c)))
        k = KyberKEM.KDF(k)
        return [k, m] if return_internals else k
    def version(self):
        if self.pke.K == 2:
            return "Kyber512"
        elif self.pke.K == 3:
            return "Kyber768"
        else:
            return "Kyber1024"
    @staticmethod
    def H(data):
        sha3 = SHA3_256.new()
        sha3.update(data.tobytes())
        d = sha3.digest()
        return np.frombuffer(d, dtype=np.uint8)
    @staticmethod
    def KDF(x):
        shake = SHAKE256.new()
        shake.update(x.tobytes())
        k = shake.read(KyberKEM.SHARED_SECRET_BYTES)
        return np.frombuffer(k, dtype=np.uint8)