[<img alt="points bar" align="right" height="36" src="../../blob/badges/.github/badges/points-bar.svg" /> <img alt="Workflow status" align="right" src="../../workflows/Autograding/badge.svg" />](../../actions/workflows/classroom.yml)

# COMP0061 -- Privacy Enhancing Technologies -- Lab on Zero Knowledge Proofs

This lab will cover Zero Knowledge Proofs.

### Structure of Labs

The structure of most of the labs will be similar: two Python files will be provided.

- The first is named `lab_X.py` and contains the structure of the code you need to complete.
- The second is named `lab_X_test.py` and contains unit tests (written for the Pytest library) that you may execute to
  partially check your answers.

Note that the tests passing is a necessary but not sufficient condition to fulfill each task. There are programs that
would make the tests pass that would still be invalid (or blatantly insecure) implementations.

The only dependency your Python code should have, besides Pytest and the standard library, is the Pycryptodome library.

The Pycryptodome documentation is [available on-line here](https://www.pycryptodome.org/src/introduction).

### Checking out code

Check out the code by using your preferred git client (e.g., git command line client, GitHub Desktop, Sourcetree).

**_Alternatively_**, you can use the GitHub Codespaces feature to check out and work on the code in the cloud.

### Setup

The intended environment for this lab is the Linux operating system with Python 3 installed.

#### Local virtual environment

To create a local virtual environment, activate the virtual environment, and install the dependencies needed for the
lab, run the following commands in the lab folder:

```shell
python3 -m venv .venv/
source .venv/bin/activate
pip3 install -r requirements.txt
```

On subsequent runs, you will only need to activate the virtualenv.

```shell
source .venv/bin/activate
```

To exit the virtual environment, run:

```shell
deactivate
```

The virtual environment is needed to run the unit tests locally.

#### Development containers

As an alternative to a local virtual environment, we provide the setup files for
[development containers](https://code.visualstudio.com/docs/remote/containers) which use
[Docker](https://docs.docker.com/get-docker/) to create a separate development environment for each repository and
install the required libraries. You don't need to know how to use Docker to use development containers. These are
supported by popular IDEs such as [Visual Studio Code](https://code.visualstudio.com/) and
[PyCharm](https://www.jetbrains.com/pycharm/).

#### GitHub Codespaces

Another alternative for running your code is to use GitHub Codespaces which use cloud-based development containers. On
GitHub, the "<> Code" button at the top right of the repository page will have a Codespaces tab. This allows you to
create a cloud-based environment to work on the assignment. You still need to use `git` to commit and push your work
when working in a codespace.

#### GitHub Classroom tests

The tests are the same as the ones that run as part of the GitHub Classroom automated marking system, so you can also
run the tests by simply committing and pushing your changes to GitHub, without the need for a local setup or even having
Python 3 installed.

### Working with unit tests

Unit tests are run from the command line by executing the command:

```sh
$ pytest -v
```

Note the `-v` flag toggles a more verbose output. If you wish to inspect the output of the full tests run you may pipe
this command to the `less` utility (execute `man less` for a full manual of the less utility):

```sh
$ pytest -v | less
```

You can also run a selection of tests associated with each task by adding the Pytest marker for each task to the Pytest
command:

```sh
$ pytest -v -m task1
```

The markers are defined in the test file and listed in `pytest.ini`.

You may also select tests to run based on their name using the `-k` flag. Have a look at the test file to find out the
function names of each test. For example the following command executes the very first test of Lab 1:

```sh
$ pytest -v -k test_provekey_correct
```

The full documentation of pytest is [available here](http://pytest.org/latest/).

### What you will have to submit

The deadline for all labs is at the end of term but labs will be progressively released throughout the term, as new
concepts are introduced. We encourage you to attempt labs as soon as they are made available and to use the dedicated
lab time to bring up any queries with the TAs.

Labs will be checked using GitHub Classroom, and the tests will be run each time you push any changes to the `main`
branch of your GitHub repository. The latest score from automarking should be shown in the Readme file. To see the test
runs, look at the Actions tab in your GitHub repository.

Make sure the submitted `lab_zkp.py` file at least satisfies the tests, without the need for any external dependency
except the Python standard libraries and the Pycryptodome library. Only submissions prior to the GitHub Classroom
deadline will be marked, so make sure you push your code in time.

To re-iterate, the tests passing is a necessary but not sufficient condition to fulfill each task. All submissions will
be checked by TAs for correctness and your final marks are based on their assessment of your work.  
For full marks, make sure you have fully filled in any sections marked with `TODO` comments, including answering any
questions in the comments of the `lab_zkp.py`.

## General Hints:

- The `setup` returns a set of parameters including the group `G`, its order `o`, a generator `g`, and an array of
  generators `hs`, shared by all functions in this exercise.
- The `to_challenge` function takes a number of group elements (EC points in this case), hashes them, and returns an
  Integer appropriate to be used as a challenge.
- As usual modify the code file in the specified location. (marked by `# TODO: YOUR CODE HERE`)
- Study the unit tests `lab_zkp_test.py` to understand how to pass them, as well as how the functions you complete are
  meant to be used.

## TASK 1 -- Prove knowledge of a DH public key's secret. \[1 point\]

- You will need to implement the Schnorr protocol in its non-interactive form to prove knowledge of a private key of a
  particular public key.
- The output of `prove_key` is a pair `(C, r)`, an `Integer` challenge and an `Integer` opening.
- Study the `verify_key` function to ensure it may verify the proof you generate.

## TASK 2 -- Prove knowledge of a Discrete Log representation. \[1 point\]

- You will have to use the extended Schnorr protocol to prove knowledge of all secrets and opening of a commitment.
- Study the function `commit` to understand the structure of the commitment. Ensure you understand the role of the
  opening value `r`.
- Study the function `verify_commitement` to ensure your proof can be verified correctly.
- The `prove_commitment` function is passed the commitment and the secrets (including the opening). It should return a
  proof consisting of the challenge and responses (multiple ones).

## TASK 3 -- Prove Equality of discrete logarithms. \[1 point\]

- In this task you need to implement `verify_dl_equality` the verification algorithm of the proof of equality of
  discrete logarithms of K and L.
- Study carefully `prove_dl_equality` to ensure your verification algorithm verifies only correct proofs.

## TASK 4 -- Prove correct encryption and knowledge of a plaintext. \[1 point\]

- In this task you need to implement both the zero knowledge proof and verification of validity of a ciphertext under
  public key pub and knowledge of the encrypted message `m`.
- In this proof you will need to combine proof of equality (for `k`) as well as proofs of multiple elements (`a` and
  `b`).

## TASK 5 -- Prove a linear relation \[1 point\]

- Study `relation` and understand how it returns a commitment to values `x0` and `x1` with a relation between them
  (`x0 = 10 x1 + 20`).
- You need to implement a function that proves knowledge of `x0`, `x1` and `r`, as well as prove that the linear
  relation between the secrets holds.
- You also need to implement the verification function for knowledge of the commitment's secrets and the linear
  relation.

## TASK 6 -- (OPTIONAL) Prove that a ciphertext is either 0 or 1 \[0 point\]

- You have to implement both proof and verification that an encrypted message under `pub` is either `0` or `1` without
  revealing which.

## TASK Q1 and Q2 -- Answer the two questions \[1 point\]

- Answer the questions in a comment block
- In Q2 you are given a snippet of code, and a test for it. Do not forget to study both before answering the question.
