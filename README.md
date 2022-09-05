# roulette
A solver used for roulette fault attacks on Kyber.

Paper: Jeroen Delvaux, "Roulette: A Diverse Family of Feasible Fault Attacks on Masked Kyber", CHES 2022, https://eprint.iacr.org/2021/1622


## Goal

By running the Python script main.py, three figures from the CHES paper are reproduced. Besides *.png images, the script generates *.dat files that contain the data points in text format. The script main.py also contains a minimal working example where a single system of 7000 inequalities for Kyber768 is verbosely solved. 

## Installation

We used Python 3.8. The following Python packages must be installed: numpy, scipy, pycryptodome, and matplotlib. Depending on your configuration of Python, this might be achieved as follows:

```
$ python3 -m pip install --upgrade pip
$ python3 -m pip install -r requirements.txt
$ cd source
$ python3 main.py
```

Alternatively, the Dockerfile can be used. The following commands might suffice:

```
$ docker build -t roulette .
$ docker run -t roulette
```

## Remarks

* Because the systems of linear inequalities are generated randomly rather than deterministically, small (insignificant) differences with the figures in the CHES paper are bound to be present.
* The Python script checks the correctness of both Kyber and randomly generated inequalities. Hence, if there would be an issue with the configuration, an error is likely thrown.
* Because we were aiming for smooth curves in the CHES paper, the default configuration of main.py is to perform many experiments, and the total execution time approached 48 hours on our system. Fortunately, the execution time can be lowered considerably by reproducing noisier versions of the CHES figures. If parameter ‘nb_of_runs’, which determines the amount of averaging, is lowered from 10 to 1, the script finishes almost 10 times faster. This can be achieved by passing an additional argument to the script, as shown below. Alternatively, the step size on the horizontal axis (the number of inequalities) can be increased by manually editing the code.

    ```
    $ python3 main.py 1
    ```