#####################################################
# COMP0061 Privacy Enhancing Technologies -- Lab on Zero Knowledge Proofs
#
# Zero Knowledge Proofs
#
# Run the tests through:
# $ pytest -v
from functools import cache

from Cryptodome.Hash import SHA256
from Cryptodome.Math.Numbers import Integer
from Cryptodome.PublicKey import ECC, _point

curves = _point._curves

Order = Integer
Generator = ECC.EccPoint
Params = tuple[Generator, list[Generator], Order]


PrivKey = Integer
PubKey = ECC.EccPoint
ProofOfKey = tuple[Integer, Integer]

Opening = Integer
Commitment = ECC.EccPoint
ProofOfCommitment = tuple[Integer, tuple[Integer, Integer, Integer, Integer, Integer]]

CipherText = tuple[ECC.EccPoint, ECC.EccPoint]
ProofOfEncryption = tuple[Integer, tuple[Integer, Integer]]

@cache
def setup() -> Params:
    """ Generates the Cryptosystem Parameters. """
    group = curves["secp224r1"]
    o: Order = group.order
    g: Generator = group.G * Integer.random_range(min_inclusive=1, max_exclusive=o)
    hs: list[Generator] = [group.G * Integer.random_range(min_inclusive=1, max_exclusive=o) for _ in range(4)]
    return g, hs, o


def key_gen(params: Params) -> tuple[PrivKey, PubKey]:
    g, h, o = params

    priv = Integer.random_range(min_inclusive=1, max_exclusive=o)
    pub = priv * g
    return priv, pub


def _point_to_bytes(p: ECC.EccPoint) -> bytes:
    x, y = p.xy
    return x.to_bytes() + y.to_bytes()

def to_challenge(elements: list[ECC.EccPoint]) -> Integer:
    """ Generates an Integer challenge by hashing a number of EC points """
    c_string = b",".join([_point_to_bytes(x) for x in elements])
    c_hash = SHA256.new(c_string).digest()
    return Integer.from_bytes(c_hash)


#####################################################
# TASK 1 -- Prove knowledge of a DH public key's secret.

def prove_key(params: Params, priv: PrivKey, pub: PubKey) -> ProofOfKey:
    """ Uses the Schnorr non-interactive protocols produce a proof of knowledge of the secret priv such that pub = priv * g.

        Outputs: a proof (c, r): c (a challenge), r (the response)
    """
    g, hs, o = params

    w = Integer.random_range(min_inclusive=1, max_exclusive=o)
    big_w = g * w
    c = to_challenge([g, pub, big_w])
    r = o + w - c * priv % o
    return c, r


def verify_key(params: Params, pub: PubKey, proof: ProofOfKey) -> bool:
    """ Schnorr non-interactive proof verification of knowledge of a secret.
    Returns a boolean indicating whether the verification was successful.
    """
    g, hs, o = params
    c, r = proof
    gw_prime = c * pub + r * g
    return to_challenge([g, pub, gw_prime]) == c


#####################################################
# TASK 2 -- Prove knowledge of a Discrete Log representation.

def commit(params: Params, secrets: list[Integer]) -> tuple[Commitment, Opening]:
    """ Produces a commitment C = r * g + Sum xi * hi, where secrets is a list of xi of length 4.
    Returns the commitment (C) and the opening (r).
    """
    assert len(secrets) == 4
    g, (h0, h1, h2, h3), o = params
    x0, x1, x2, x3 = secrets
    r = Integer.random_range(min_inclusive=1, max_exclusive=o)
    C = x0 * h0 + x1 * h1 + x2 * h2 + x3 * h3 + r * g
    return C, r


def prove_commitment(params: Params, C: Commitment, r: Opening, secrets: list[Integer]) -> ProofOfCommitment:
    """ Prove knowledge of the secrets within a commitment, as well as the opening of the commitment.

    Args: C (the commitment), r (the opening of the commitment), and secrets (a list of secrets).
    Returns: a challenge (c) and a list of responses.
    """
    g, (h0, h1, h2, h3), o = params
    x0, x1, x2, x3 = secrets

    w = [Integer.random_range(min_inclusive=1, max_exclusive=o) for _ in range(4)]
    big_w = w[0] * h0 + w[1] * h1 + w[2] * h2 + w[3] * h3
    c = to_challenge([g, h0, h1, h2, h3, C, big_w])
    responses = []
    for i in range(4):
        responses.append(o + w[i] - c * secrets[i] % o)
    responses.append(-r*c)
    return c, responses


def verify_commitments(params: Params, C: Commitment, proof: ProofOfCommitment) -> bool:
    """ Verify a proof of knowledge of the commitment.
    Return a boolean denoting whether the verification succeeded. """
    g, (h0, h1, h2, h3), o = params
    c, responses = proof
    (r0, r1, r2, r3, rr) = responses

    Cw_prime = c * C + r0 * h0 + r1 * h1 + r2 * h2 + r3 * h3 + rr * g
    c_prime = to_challenge([g, h0, h1, h2, h3, C, Cw_prime])
    valid = c_prime == c
    return valid


#####################################################
# TASK 3 -- Prove Equality of discrete logarithms.

def gen2_keys(params: Params) -> tuple[PrivKey, PubKey, PubKey]:
    """ Generate two related public keys K = x * g and L = x * h0. """
    g, (h0, h1, h2, h3), o = params
    x = Integer.random_range(min_inclusive=1, max_exclusive=o)

    K = g * x
    L = h0 * x

    return x, K, L


def prove_dl_equality(params: Params, x: PrivKey, K: PubKey, L: PubKey) -> ProofOfKey:
    """ Generate a ZK proof that two public keys K, L have the same secret private key x, as well as knowledge of this private key. """
    g, (h0, h1, h2, h3), o = params
    w = Integer.random_range(min_inclusive=1, max_exclusive=o)
    Kw = w * g
    Lw = w * h0

    c = to_challenge([g, h0, K, Kw, L, Lw])

    r = (w - c * x) % o
    return c, r


def verify_dl_equality(params: Params, K: PubKey, L: PubKey, proof: ProofOfKey) -> bool:
    """ Return whether the verification of equality of two discrete logarithms succeeded. """
    g, (h0, h1, h2, h3), o = params
    c, r = proof

    # TODO: YOUR CODE HERE
    ...
    valid = ...

    return valid


#####################################################
# TASK 4 -- Prove correct encryption and knowledge of a plaintext.

def encrypt(params: Params, pub: PubKey, m: int) -> tuple[Integer, CipherText]:
    """ Encrypt a message m under a public key pub.
        Returns both the randomness and the ciphertext.
    """
    g, (h0, h1, h2, h3), o = params
    k = Integer.random_range(min_inclusive=1, max_exclusive=o)
    ciphertext = (g * k, pub * k + h0 * m)
    return k, ciphertext


def prove_enc(params: Params, pub: PubKey, ciphertext: CipherText, k: Integer, m: int) -> ProofOfEncryption:
    """ Prove in ZK that the ciphertext is well-formed and knowledge of the message encrypted as well.

        Return the proof: challenge and the responses.
    """
    g, (h0, h1, h2, h3), o = params
    a, b = ciphertext

    # TODO: YOUR CODE HERE:
    ...
    c = ...
    response = ...

    return c, response


def verify_enc(params: Params, pub: PubKey, ciphertext: CipherText, proof: ProofOfEncryption) -> bool:
    """ Verify the proof of correct encryption and knowledge of a ciphertext. """
    g, (h0, h1, h2, h3), o = params
    a, b = ciphertext
    c, (rk, rm) = proof

    # TODO: YOUR CODE HERE
    ...
    valid = ...

    return valid


#####################################################
# TASK 5 -- Prove a linear relation

def relation(params: Params, x1: int) -> tuple[Commitment, int, int, Opening]:
    """ Returns a commitment C to x0 and x1, such that x0 = 10 x1 + 20, as well as x0, x1 and the commitment opening r.
    """
    g, (h0, h1, h2, h3), o = params
    r = Integer.random_range(min_inclusive=1, max_exclusive=o)

    x0 = (x1 * 10 + 20)
    C = g * r + h1 * x1 + h0 * x0

    return C, x0, x1, r


def prove_x0eq10x1plus20(params: Params, C: Commitment, x0: int, x1: int, r: Opening) -> tuple[Integer, tuple[Integer, Integer]]:
    """ Prove C is a commitment to x0 and x1 and that x0 = 10 x1 + 20. """
    g, (h0, h1, h2, h3), o = params

    # TODO: YOUR CODE HERE
    ...
    c = ...
    response = ...

    return c, response


def verify_x0eq10x1plus20(params: Params, C: Commitment, proof: tuple[Integer, tuple[Integer, Integer]]) -> bool:
    """ Verify that proof of knowledge of C and x0 = 10 x1 + 20. """
    g, (h0, h1, h2, h3), o = params

    # TODO: YOUR CODE HERE
    ...
    valid = ...

    return valid


#####################################################
# TASK 6 -- (OPTIONAL) Prove that a ciphertext is either 0 or 1


def bin_encrypt(params: Params, pub: PubKey, m: int) -> tuple[Integer, CipherText]:
    """ Encrypt a binary value m under public key pub """
    assert m in [0, 1]
    g, (h0, h1, h2, h3), o = params

    k = Integer.random_range(min_inclusive=1, max_exclusive=o)
    return k, (g * k, pub * k + h0 * m)


def prove_bin(params: Params, pub: PubKey, ciphertext, k: Integer, m: int) -> ProofOfEncryption:
    """ Prove a ciphertext is valid and encrypts a binary value either 0 or 1. """
    # TODO: YOUR CODE HERE
    ...
    c = ...
    response = ...

    return c, response


def verify_bin(params, pub, ciphertext, proof):
    """ verify that proof that a ciphertext is a binary value 0 or 1. """
    # TODO: YOUR CODE HERE
    ...
    valid = ...

    return valid


def test_bin_correct():
    """ Test that a correct proof verifies """
    # TODO: YOUR CODE HERE
    ...

def test_bin_incorrect():
    """ Prove that incorrect proofs fail. """
    # TODO: YOUR CODE HERE
    ...


#####################################################
# TASK Q1 - Answer the following question:
#
# The interactive Schnorr protocol (see Slide 9 of Week 4) offers "plausible deniability" when performed with an honest verifier.
# The transcript of the 3 step interactive protocol could be simulated without knowledge of the secret (see Slide 14 of Week 4).
# Therefore, the verifier cannot use it to prove to a third party that the holder of secret took part in the protocol acting as the prover.
#
# Does "plausible deniability" hold against a dishonest verifier that deviates from the Schnorr identification protocol?
# Justify your answer by describing what a dishonest verifier may do.

""" TODO: Your answer here. """

#####################################################
# TASK Q2 - Answer the following question:
#
# Consider the function "prove_something" below, that implements a zero-knowledge proof on commitments KX and KY to x and y respectively.
# Note that the prover only knows secret y.
# What statement is a verifier, given the output of this function, convinced of?
#
# Hint: Look at "test_prove_something" too.

""" TODO: Your answer here. """


def prove_something(params, KX, KY, y):
    g, _, o = params

    # Simulate proof for KX
    # r = wx - cx => g^w = g^r * KX^c
    rx = Integer.random_range(min_inclusive=1, max_exclusive=o)
    c1 = Integer.random_range(min_inclusive=1, max_exclusive=o)
    W_KX = rx * g + c1 * KX

    # Build proof for KY
    wy = Integer.random_range(min_inclusive=1, max_exclusive=o)
    W_KY = wy * g
    c = to_challenge([g, KX, KY, W_KX, W_KY])

    # Build so that: c1 + c2 = c (mod o)
    c2 = (c - c1) % o
    ry = (wy - c2 * y) % o

    # return proof
    return c1, c2, rx, ry


def test_prove_something():
    params = setup()
    g, hs, o = params

    # Commit to x and y
    x = Integer.random_range(min_inclusive=1, max_exclusive=o)
    y = Integer.random_range(min_inclusive=1, max_exclusive=o)
    KX = g * x
    KY = g * y

    # Pass only y
    c1, c2, rx, ry = prove_something(params, KX, KY, y)

    # Verify the proof
    W_KX = rx * g + c1 * KX
    W_KY = ry * g + c2 * KY
    c = to_challenge([g, KX, KY, W_KX, W_KY])
    assert c % o == (c1 + c2) % o
