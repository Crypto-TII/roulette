#!/usr/bin/python3

from kyber import KyberKEM
import test_kyber
from rng import RNG_OS
import solver
import numpy as np
import matplotlib.pyplot as plt
import time
import sys

def minimal_working_example():
    """Solves one system of inequalities and tracks the convergence rate"""
    print("Minimal working example...")
    K = 3
    nb_of_inequalities = 7000
    rng = RNG_OS()
    kem = KyberKEM(K, rng)
    [public_key, private_key, s, e] = kem.keygen(return_internals=True)
    solution = np.concatenate((s.ravel(), e.ravel()))
    [a, b] = solver.generate_inequalities(kem, public_key, nb_of_inequalities)
    is_geq_zero = solver.evaluate_inequalities_fast(a, b, solution)
    time_start = time.time()
    solver.solve_inequalities(kem, a, b, is_geq_zero,
            verbose=True, solution=solution)
    time_end = time.time()
    print("Elapsed time: {:.1f} seconds".format(time_end-time_start))

def figure_inequality_filtering(nb_of_runs = 10):
    """Reproduces a figure from the CHES 2022 paper"""
    print("Generating figure of inequality filtering...")
    filename = "solver-inequality-filtering"
    K = 2
    nb_of_inequalities = np.arange(0, 15000+1, step = 500)
    header = "NB_OF_INEQUALITIES FILTERED UNFILTERED"
    legend = ["Filtered", "Unfiltered"]
    nb_of_points = len(nb_of_inequalities)
    nb_of_inequalities_max = max(nb_of_inequalities)
    prob_correct = np.zeros((nb_of_points, 2, nb_of_runs), dtype=float)
    rng = RNG_OS()
    kem = KyberKEM(K, rng)
    indices = [None, 9]
    for k in range(nb_of_runs):
        for j in range(2):
            print(legend[j])
            [public_key, private_key, s, e] = kem.keygen(
                    return_internals=True)
            solution = np.concatenate((s.ravel(), e.ravel()))
            [a, b] = solver.generate_inequalities(kem, public_key,
                    nb_of_inequalities_max, index=indices[j])
            is_geq_zero = solver.evaluate_inequalities_fast(a, b, solution)
            for i in range(nb_of_points):
                print('Solving {:d} inequalities'
                        .format(nb_of_inequalities[i]))
                ind = np.random.permutation(nb_of_inequalities_max)
                ind = ind[:nb_of_inequalities[i]]
                x = solver.solve_inequalities(kem, a[ind,:], b[ind],
                        is_geq_zero[ind], verbose=False)
                nb_correct = np.count_nonzero(solution == x)
                print("Number of correctly guessed unknowns: {:d}/{:d}"
                        .format(nb_correct, len(solution)))
                prob_correct[i, j, k] = nb_correct / len(x)
    prob_correct = np.mean(prob_correct, axis = 2)
    write_to_file(filename + ".dat", header, nb_of_inequalities, prob_correct)
    plot(filename + ".png", nb_of_inequalities, prob_correct, legend)

def figure_security_level(nb_of_runs = 10):
    """Reproduces a figure from the CHES 2022 paper"""
    print("Generating figure of security level...")
    filename = "solver-security-level"
    K = [2, 3, 4]
    nb_of_inequalities = np.arange(0, 15000+1, step=500)
    header = "NB_OF_INEQUALITIES TWO THREE FOUR"
    legend = ["Kyber512", "Kyber768", "Kyber1024"]
    (nb_of_curves, nb_of_points) = (len(K), len(nb_of_inequalities))
    nb_of_inequalities_max = max(nb_of_inequalities)
    prob_correct = np.zeros((nb_of_points, nb_of_curves, nb_of_runs),
            dtype=float)
    rng = RNG_OS()
    for j in range(nb_of_curves):
        kem = KyberKEM(K[j], rng)
        for k in range(nb_of_runs):
            [public_key, private_key, s, e] = kem.keygen(
                    return_internals=True)
            solution = np.concatenate((s.ravel(), e.ravel()))
            [a, b] = solver.generate_inequalities(kem, public_key,
                    nb_of_inequalities_max)
            is_geq_zero = solver.evaluate_inequalities_fast(a, b, solution)
            for i in range(nb_of_points):
                print('Solving {:d} inequalities'
                        .format(nb_of_inequalities[i]))
                ind = np.random.permutation(nb_of_inequalities_max)
                ind = ind[:nb_of_inequalities[i]]
                x = solver.solve_inequalities(kem, a[ind,:], b[ind],
                        is_geq_zero[ind], verbose=False)
                nb_correct = np.count_nonzero(solution == x)
                print("Number of correctly guessed unknowns: {:d}/{:d}"
                        .format(nb_correct, len(solution)))
                prob_correct[i, j, k] = nb_correct / len(x)
    prob_correct = np.mean(prob_correct, axis = 2)
    write_to_file(filename + ".dat", header, nb_of_inequalities, prob_correct)
    plot(filename + ".png", nb_of_inequalities, prob_correct, legend)

def figure_corrupted_inequalities(nb_of_runs = 10):
    """Reproduces a figure from the CHES 2022 paper"""
    print("Generating figure of corrupted inequalities...")
    filename = "solver-corrupt"
    K = 2
    nb_of_inequalities = np.arange(0, 30000+1, step = 1000)
    percentage_corrupt = [0, 10, 20, 30, 40, 50, 60]
    header = "NB_OF_INEQUALITIES P" + ' P'.join(map(str, percentage_corrupt))
    legend = [str(p) + "%" for p in percentage_corrupt]
    nb_of_inequalities_max = max(nb_of_inequalities)
    nb_of_points = len(nb_of_inequalities)
    nb_of_curves = len(percentage_corrupt)
    prob_correct = np.zeros((nb_of_points, nb_of_curves, nb_of_runs),
            dtype=float)
    rng = RNG_OS()
    kem = KyberKEM(K, rng)
    for k in range(nb_of_runs):
        [public_key, private_key, s, e] = kem.keygen(return_internals=True)
        solution = np.concatenate((s.ravel(), e.ravel()))
        [a, b] = solver.generate_inequalities(kem, public_key,
                nb_of_inequalities_max)
        is_geq_zero = solver.evaluate_inequalities_fast(a, b, solution)
        for i in range(nb_of_points):
            print('Solving {:d} inequalities'
                    .format(nb_of_inequalities[i]))
            for j in range(nb_of_curves):
                ind = np.random.permutation(nb_of_inequalities_max)
                ind = ind[:nb_of_inequalities[i]]
                is_geq_zero_corrupt = solver.corrupt_inequalities(
                        is_geq_zero[ind], percentage_corrupt[j]/100)
                x = solver.solve_inequalities(kem, a[ind,:], b[ind],
                        is_geq_zero_corrupt, verbose=False)
                nb_correct = np.count_nonzero(solution == x)
                print("Number of correctly guessed unknowns: {:d}/{:d}"
                        .format(nb_correct, len(solution)))
                prob_correct[i, j, k] = nb_correct / len(x)
    prob_correct = np.mean(prob_correct, axis = 2)
    write_to_file(filename + ".dat", header, nb_of_inequalities, prob_correct)
    plot(filename + ".png", nb_of_inequalities, prob_correct, legend)

def write_to_file(filename, header, nb_of_inequalities, prob_correct):
    """Exports data points such that LaTeX TikZ/pgfplots can import them"""
    f = open(filename, "w")
    f.write(header + "\n")
    for i in range(len(nb_of_inequalities)):
        f.write(str(nb_of_inequalities[i]) + " " + ' '.join(map(str,
                np.round(prob_correct[i], decimals=3))) + "\n")
    f.close()

def plot(filename, nb_of_inequalities, prob_correct, legend):
    plt.plot(nb_of_inequalities, prob_correct)
    plt.gca().set_ylim([0.0, 1.0])
    plt.xlabel('Number of inequalities')
    plt.ylabel('Probability of correctly guessing an unknown')
    plt.legend(legend, loc="lower right")
    plt.savefig(filename)
    plt.close()

def main():
    nb_of_runs = 10
    if len(sys.argv) == 2:
        try:
            nb_of_runs = int(sys.argv[1])
        except ValueError:
            raise TypeError("Number of runs must be an integer")
        if nb_of_runs < 1:
            raise TypeError("Number of runs must exceed 0")
    test_kyber.main()
    solver.test()
    minimal_working_example()
    figure_inequality_filtering(nb_of_runs=nb_of_runs)
    figure_security_level(nb_of_runs=nb_of_runs)
    figure_corrupted_inequalities(nb_of_runs=nb_of_runs)

if __name__ == "__main__":
    main()