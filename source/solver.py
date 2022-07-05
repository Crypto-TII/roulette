from kyber import KyberPKE, KyberKEM
from rng import RNG_OS
import numpy as np
from scipy.stats import binom, norm
import time
import math

def poly_multiplier_to_matrix(poly, row_index=None):
    p = poly.astype(np.int16)
    if row_index is None:
        N = len(p)
        r = np.zeros((N, N), dtype=np.int16)
        for i in range(N):
            r[i,:] = np.concatenate((np.flip(p[:i+1]), -np.flip(p[i+1:])))
    else:
        r = np.concatenate((np.flip(p[:row_index+1]),
                -np.flip(p[row_index+1:])))
    return r

def manipulate_ciphertext(pke, c, index):
    c2 = np.copy(c)
    nb_of_bytes = KyberPKE.N*pke.DV//8
    v = KyberPKE.decode(c[-nb_of_bytes:], pke.DV, KyberPKE.N)
    v_mod = (v[index] + 2**(pke.DV - 2)) % (2**(pke.DV))
    error = KyberPKE.decompress(v_mod, pke.DV) \
            - KyberPKE.decompress(v[index], pke.DV)
    error %= KyberPKE.Q
    v[index] = v_mod
    v = KyberPKE.encode(v, pke.DV)
    c2[-nb_of_bytes:] = v
    return [c2, error]

def generate_inequalities(
        kem,
        public_key, 
        nb_of_inequalities, 
        index=None, 
        bias_threshold=None, 
        max_nb_of_encapsulations=None,
        return_manipulation=False,
        verbose=True):
    if verbose:
        print("Generating {:d} inequalities for {:s}..."
                .format(nb_of_inequalities, kem.version()))
    (K, N) = (kem.pke.K, KyberPKE.N)
    a = np.zeros((nb_of_inequalities, 2*K*N), dtype=np.int16)
    b = np.zeros((nb_of_inequalities), dtype=np.int16)
    if return_manipulation:
        manipulated_indices = np.zeros(nb_of_inequalities, dtype=np.uint8)
        ciphertexts = np.zeros((nb_of_inequalities, 
                (K*kem.pke.DU + kem.pke.DV)*N//8), dtype=np.uint8)
        manipulated_ciphertexts = np.zeros((nb_of_inequalities, 
                (K*kem.pke.DU + kem.pke.DV)*N//8), dtype=np.uint8)
        shared_secrets = np.zeros((nb_of_inequalities,
                KyberKEM.SHARED_SECRET_BYTES), dtype=np.uint8)
        manipulated_shared_secrets = np.zeros((nb_of_inequalities,
                KyberKEM.SHARED_SECRET_BYTES), dtype=np.uint8)
    for i in range(nb_of_inequalities):
        done = False
        nb_of_encapsulations = 0
        lowest_bias = 10000
        while not done:
            c, ss, m, r, e1, du, e2, dv, ss_pre = kem.encapsulate(public_key,
                    return_internals=True)
            b2 = e2 + dv
            m = np.unpackbits(m, bitorder='little')
            _, error = manipulate_ciphertext(kem.pke, c, np.arange(N))
            b2[np.logical_and(error == 832, m == 0)] -= 1
            b2[np.logical_and(error == 833, m == 1)] += 1
            bias = abs(b2)
            ind = np.argmin(bias) if index is None else index
            if return_manipulation:
                manipulated_indices[i] = ind
                ciphertexts[i,:] = c
                manipulated_ciphertexts[i,:], _ = \
                        manipulate_ciphertext(kem.pke, c, ind)
                shared_secrets[i,:] = ss
                manipulated_shared_secrets[i,:] = KyberKEM.KDF(
                    np.concatenate((ss_pre,
                    KyberKEM.H(manipulated_ciphertexts[i,:]))))
            if bias[ind] < lowest_bias:
                lowest_bias = bias[ind]
                b[i] = b2[ind]
                for j in range(K):
                    a[i, j*N:(j+1)*N] = poly_multiplier_to_matrix(
                            -e1[j,:] - du[j,:], row_index=ind)
                    a[i, (K+j)*N:(K+j+1)*N] = poly_multiplier_to_matrix(
                            r[j,:], row_index=ind)
            nb_of_encapsulations += 1
            done = (bias_threshold is None) \
                    or (bias[ind] <= bias_threshold) \
                    or ((max_nb_of_encapsulations is not None) and \
                    (nb_of_encapsulations >= max_nb_of_encapsulations))
    return [a, b, manipulated_indices, ciphertexts, manipulated_ciphertexts, \
        shared_secrets, manipulated_shared_secrets] if return_manipulation \
        else [a, b]

def evaluate_inequalities_slow(
        kem,
        private_key,
        manipulated_indices,
        manipulated_ciphertexts, 
        manipulated_shared_secrets):
    nb_of_inequalities = manipulated_ciphertexts.shape[0]
    is_geq_zero = np.full((nb_of_inequalities), False)
    for i in range(nb_of_inequalities):
        ss = kem.decapsulate(private_key, manipulated_ciphertexts[i,:],
            roulette_index=manipulated_indices[i])
        is_geq_zero[i] = not np.array_equal(ss,
                manipulated_shared_secrets[i,:])
    return is_geq_zero

def evaluate_inequalities_fast(a, b, solution):
        return (np.matmul(a, solution) + b) >= 0

def corrupt_inequalities(is_geq_zero, prob_success_is_missed, verbose=True):
    is_geq_zero_corrupt = np.copy(is_geq_zero)
    ind, = np.where(is_geq_zero == False)
    miss = np.random.binomial(1, prob_success_is_missed, size=len(ind))
    ind2, = np.where(miss == 1)
    is_geq_zero_corrupt[ind[ind2]] = True
    print("Corrupted {:d} out of {:d} inequalities"
            .format(len(ind2), len(is_geq_zero)))
    return is_geq_zero_corrupt

def generate_equalities(kem, public_key, verbose=True):
    if verbose:
        print("Generating equalities for {:s}...".format(kem.version()))
    (K, N) = (kem.pke.K, KyberPKE.N)
    (t, rho) = np.split(public_key, [K * N *3//2])
    t = np.reshape(KyberPKE.decode(t, 12, K * N), (K, N))
    A = kem.pke.generate_A(rho, transpose=False)
    a = np.hstack((np.zeros((K*N, K*N), dtype=np.int32),
            2285*np.eye(K*N, dtype=np.int32)))
    b = np.zeros((K*N), dtype=np.int32)
    for i in range(K):
        b[i*N:(i+1)*N] = -kem.pke.INTT(t[i])
        for j in range(K):
            a[i*N:(i+1)*N,j*N:(j+1)*N] = poly_multiplier_to_matrix(
                    kem.pke.INTT(A[i,j]))
    return a, b

def solve_inequalities(kem, a, b, is_geq_zero, max_nb_of_iterations=16,
            verbose=True, solution=None):
    if verbose:
        print("Solving inequalities...")
    eta = kem.pke.ETA1
    [nb_of_inequalities, nb_of_unknowns] = a.shape
    guess = np.zeros((nb_of_unknowns), dtype=int)
    if verbose and solution is not None:
        nb_correct = np.count_nonzero(solution == guess)
        print("Number of correctly guessed unknowns: {:d}/{:d}"
                .format(nb_correct, len(solution)))
    if nb_of_inequalities == 0:
        return guess
    nb_of_values = 2*eta + 1
    x = np.arange(-eta, eta+1, dtype=np.int8)
    x_pmf = binom.pmf(x + eta, 2*eta, 0.5)
    x_pmf = np.repeat(x_pmf.reshape(1,-1), nb_of_unknowns, axis=0)
    a = a.astype(np.int16)
    a_squared = np.square(a)
    prob_geq_zero = np.zeros((nb_of_inequalities), dtype=float)
    p_failure_is_observed = np.count_nonzero(is_geq_zero) / nb_of_inequalities
    mean = np.matmul(x_pmf, x)
    variance = np.matmul(x_pmf, np.square(x)) - np.square(mean)
    mean = np.matmul(a, mean)
    variance = np.matmul(a_squared, variance)
    zscore = np.divide(mean + 0.5 + b, np.sqrt(variance))
    p_failure_is_reality = 1 - norm.cdf(zscore)
    p_failure_is_reality = np.mean(p_failure_is_reality)
    p_inequality_is_correct = min(
            p_failure_is_reality / p_failure_is_observed, 1.0)
    prob_geq_zero[is_geq_zero] = p_inequality_is_correct
    fitness = np.zeros((max_nb_of_iterations), dtype=float)
    fitness_max = np.sum(np.maximum(prob_geq_zero, 1 - prob_geq_zero))
    for z in range(max_nb_of_iterations):
        if verbose:
            print("Iteration " + str(z))
            time_start = time.time()
        mean = np.matmul(x_pmf, x)
        variance = np.matmul(x_pmf, np.square(x)) - np.square(mean)
        mean = np.multiply(a, np.repeat(mean[np.newaxis,:],
                nb_of_inequalities, axis=0))
        variance = np.multiply(
            a_squared,
            np.repeat(variance[np.newaxis,:], nb_of_inequalities, axis=0))
        mean = mean.sum(axis=1).reshape(-1,1).repeat(nb_of_unknowns, axis=1) \
                - mean
        mean += b[:, np.newaxis]
        variance = variance.sum(axis=1).reshape(-1,1).repeat(nb_of_unknowns,
                axis=1) - variance
        variance = np.clip(variance, 1, None)
        psuccess = np.zeros((nb_of_values, nb_of_inequalities,
                nb_of_unknowns), dtype=float)
        for j in range(nb_of_values):
            zscore = np.divide(a*x[j] + mean + 0.5, np.sqrt(variance))
            psuccess[j,:,:] = norm.cdf(zscore)
        psuccess = np.transpose(psuccess, axes=[2,0,1])
        psuccess = \
            np.multiply(psuccess, prob_geq_zero[np.newaxis,np.newaxis,:]) + \
            np.multiply(1-psuccess, 1-prob_geq_zero[np.newaxis,np.newaxis,:])
        psuccess = np.clip(psuccess, 10e-5, None)
        psuccess = np.sum(np.log(psuccess), axis=2)
        row_means = psuccess.max(axis=1)
        psuccess -= row_means[:, np.newaxis]
        psuccess = np.exp(psuccess)
        x_pmf = np.multiply(psuccess, x_pmf)
        row_sums = x_pmf.sum(axis=1)
        x_pmf /= row_sums[:, np.newaxis]
        guess = x[np.argmax(x_pmf, axis=1)]
        fit = (np.matmul(a, guess) + b >= 0).astype(float)
        fit = np.dot(fit, prob_geq_zero) + np.dot(1-fit, 1-prob_geq_zero)
        fitness[z] = fit / fitness_max
        if verbose:
            time_end = time.time()
            print("Elapsed time: {:.1f} seconds".format(time_end-time_start))
            print("Fitness {:.2f}%".format(fitness[z]*100))
            if solution is not None:
                nb_correct = np.count_nonzero(solution == guess)
                print("Number of correctly guessed unknowns: {:d}/{:d}"
                        .format(nb_correct, len(solution)))
        if (z > 1) and fitness[z-1] >= fitness[z]:
            break
    return guess

def test_inequalities():
    rng = RNG_OS()
    nb_of_inequalities = 1000
    for K in [2, 3, 4]:
        kem = KyberKEM(K, rng)
        [public_key, private_key, s, e] = kem.keygen(return_internals=True)
        solution = np.concatenate((s.ravel(), e.ravel()))
        [a, b, manipulated_indices, _, manipulated_ciphertexts, _, 
                manipulated_shared_secrets] = generate_inequalities(kem,
                public_key, nb_of_inequalities, return_manipulation=True)
        is_geq_zero1 = evaluate_inequalities_slow(kem, private_key,
                manipulated_indices, manipulated_ciphertexts, 
                manipulated_shared_secrets)
        is_geq_zero2 = evaluate_inequalities_fast(a, b, solution)
        if np.any(is_geq_zero1 != is_geq_zero2):
            raise ValueError("Inequalities test failed")    
        print("Inequalities test passed")

def test_equalities():
    rng = RNG_OS()
    for K in [2, 3, 4]:
        kem = KyberKEM(K, rng)
        [public_key, private_key, s, e] = kem.keygen(return_internals=True)
        solution = np.concatenate((s.ravel(), e.ravel()))
        [a, b] = generate_equalities(kem, public_key)
        r = (np.matmul(a, solution) + b) % KyberPKE.Q
        if r.any():
            raise ValueError("Equalities test failed")
        print("Equalities test passed")

def test():
    print("Testing solver...")
    test_inequalities()
    test_equalities()