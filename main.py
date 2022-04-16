#!/usr/bin/python3

from kyber import KyberKEM
import test_kyber
from rng import RNG_OS
import solver
import numpy as np
import matplotlib.pyplot as plt

def minimal_working_example():
	K = 2
	nb_of_inequalities = 8000
	rng = RNG_OS()
	kem = KyberKEM(K, rng)
	[public_key, private_key, s, e] = kem.keygen(return_internals=True)
	solution = np.concatenate((s.ravel(), e.ravel()))
	[a, b] = solver.generate_inequalities(kem, public_key, nb_of_inequalities)
	is_geq_zero = solver.evaluate_inequalities_fast(a, b, solution)
	solver.solve_inequalities(kem, a, b, is_geq_zero, verbose=True, solution=solution)

def figure_inequality_filtering():
	K = 2
	nb_of_inequalities = np.arange(0, 15000+1, step = 1000)
	nb_of_runs = 10
	N = len(nb_of_inequalities)
	prob_correct = np.zeros((N, 2, nb_of_runs), dtype=float)
	rng = RNG_OS()
	kem = KyberKEM(K, rng)
	indices = [None, 9]
	for i in range(N):
		for k in range(nb_of_runs):
			[public_key, private_key, s, e] = kem.keygen(return_internals=True)
			solution = np.concatenate((s.ravel(), e.ravel()))
			for j in range(2):
				[a, b] = solver.generate_inequalities(kem, public_key, nb_of_inequalities[i], index=indices[j])
				is_geq_zero = solver.evaluate_inequalities_fast(a, b, solution)
				x = solver.solve_inequalities(kem, a, b, is_geq_zero, verbose=False)
				nb_correct = np.count_nonzero(solution == x)
				print("Number of correctly guessed unknowns: " + str(nb_correct))
				prob_correct[i, j, k] = nb_correct / len(x)
	prob_correct = np.mean(prob_correct, axis = 2)
	header = "NB_OF_INEQUALITIES FILTERED UNFILTERED"
	write_to_file("solver-inequality-filtering.dat", header, nb_of_inequalities, prob_correct)
	plot(nb_of_inequalities, prob_correct, ["Filtered", "Unfiltered"])

def figure_security_level():
	K = [2, 3, 4] 
	nb_of_inequalities = np.arange(0, 15000+1, step = 1000)
	nb_of_runs = 10
	N = len(nb_of_inequalities)
	prob_correct = np.zeros((N, 3, nb_of_runs), dtype=float)
	rng = RNG_OS()
	for i in range(3):
		kem = KyberKEM(K[i], rng)
		for k in range(nb_of_runs):
			[public_key, private_key, s, e] = kem.keygen(return_internals=True)
			solution = np.concatenate((s.ravel(), e.ravel()))
			for j in range(N):
				[a, b] = solver.generate_inequalities(kem, public_key, nb_of_inequalities[j])
				is_geq_zero = solver.evaluate_inequalities_fast(a, b, solution)
				x = solver.solve_inequalities(kem, a, b, is_geq_zero, verbose=False)
				nb_correct = np.count_nonzero(solution == x)
				print("Number of correctly guessed unknowns: " + str(nb_correct))
				prob_correct[j, i, k] = nb_correct / len(x)
	prob_correct = np.mean(prob_correct, axis = 2)
	header = "NB_OF_INEQUALITIES TWO THREE FOUR"
	write_to_file("solver-security-level.dat", header, nb_of_inequalities, prob_correct)
	plot(nb_of_inequalities, prob_correct, ["K=2", "K=3", "K=4"])

def figure_corrupted_inequalities():
	K = 2
	nb_of_inequalities = np.arange(0, 25000+1, step = 1000)
	nb_of_runs = 5
	percentage_corrupt = [0, 10, 20, 30, 40, 50, 60]
	(N, M) = (len(nb_of_inequalities), len(percentage_corrupt))
	prob_correct = np.zeros((N, M, nb_of_runs), dtype=float)
	rng = RNG_OS()
	kem = KyberKEM(K, rng)
	for i in range(N):
		for k in range(nb_of_runs):
			[public_key, private_key, s, e] = kem.keygen(return_internals=True)
			solution = np.concatenate((s.ravel(), e.ravel()))
			[a, b] = solver.generate_inequalities(kem, public_key, nb_of_inequalities[i])
			is_geq_zero = solver.evaluate_inequalities_fast(a, b, solution)
			for j in range(M):
				is_geq_zero_corrupt = solver.corrupt_inequalities(is_geq_zero, percentage_corrupt[j]/100)
				x = solver.solve_inequalities(kem, a, b, is_geq_zero_corrupt, verbose=False)
				nb_correct = np.count_nonzero(solution == x)
				print("Number of correctly guessed unknowns: " + str(nb_correct))
				prob_correct[i, j, k] = nb_correct / len(x)
	prob_correct = np.mean(prob_correct, axis = 2)
	header = "NB_OF_INEQUALITIES P" + ' P'.join(map(str, percentage_corrupt))
	write_to_file("solver-corrupt.dat", header, nb_of_inequalities, prob_correct)
	legend = [str(p) + "%" for p in percentage_corrupt]
	plot(nb_of_inequalities, prob_correct, legend)

def write_to_file(filename, header, nb_of_inequalities, prob_correct):
	f = open(filename, "w")
	f.write(header + "\n")
	for i in range(len(nb_of_inequalities)):
		f.write(str(nb_of_inequalities[i]) + " " + ' '.join(map(str, np.round(prob_correct[i], decimals=3))) + "\n")
	f.close()

def plot(nb_of_inequalities, prob_correct, legend):
	plt.plot(nb_of_inequalities, prob_correct)
	plt.gca().set_ylim([0.0, 1.0])
	plt.xlabel('Number of inequalities')
	plt.ylabel('Probability of correctly guessing an unknown')
	plt.legend(legend)
	plt.show()

def main():
	test_kyber.main()
	solver.test()
	minimal_working_example()
	#figure_inequality_filtering()
	#figure_security_level()
	#figure_corrupted_inequalities()

if __name__ == "__main__":
    main()