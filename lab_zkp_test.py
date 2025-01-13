#####################################################
# COMP0061 Privacy Enhancing Technologies -- Lab on Zero Knowledge Proofs
#
# Zero Knowledge Proofs
#
# Run the tests through:
# $ pytest -v

import pytest

from lab_zkp import *


#####################################################
# TASK 1 -- Prove knowledge of a DH public key's 
#           secret.

@pytest.mark.task1
def test_provekey_correct():
    params = setup()

    # Correct proof
    priv, pub = key_gen(params)
    proof = prove_key(params, priv, pub)
    assert verify_key(params, pub, proof)


@pytest.mark.task1
def test_provekey_incorrect():
    params = setup()

    priv, pub = key_gen(params)

    # Incorrect proof
    priv2, pub2 = key_gen(params)
    proof2 = prove_key(params, priv2, pub2)
    assert not verify_key(params, pub, proof2)


#####################################################
# TASK 2 -- Prove knowledge of a Discrete Log 
#           representation.

@pytest.mark.task2
def test_prove_commit_correct():
    params = setup()

    # Correct proof
    secrets = [Integer(i) for i in [10, 20, 30, 40]]
    C, r = commit(params, secrets)
    proof = prove_commitment(params, C, r, secrets)
    assert verify_commitments(params, C, proof)


@pytest.mark.task2
def test_prove_commit_incorrect():
    params = setup()

    # Correct proof
    secrets = [Integer(i) for i in [10, 20, 30, 40]]
    C, r = commit(params, secrets)
    proof = prove_commitment(params, C, r, secrets)

    # Incorrect proof
    secrets2 = [Integer(i) for i in [10, 20, 30, 40]]
    C2, r2 = commit(params, secrets2)
    proof2 = prove_commitment(params, C2, r2, secrets2)
    assert not verify_commitments(params, C, proof2)
    assert not verify_commitments(params, C2, proof)


#####################################################
# TASK 3 -- Prove Equality of discrete logarithms.
#

@pytest.mark.task3
def test_prove_equality_correct():
    params = setup()

    x, K, L = gen2_keys(params)
    proof = prove_dl_equality(params, x, K, L)

    assert verify_dl_equality(params, K, L, proof)


@pytest.mark.task3
def test_prove_equality_incorrect():
    params = setup()

    x, K, L = gen2_keys(params)
    _, _, L2 = gen2_keys(params)

    proof = prove_dl_equality(params, x, K, L)

    assert not verify_dl_equality(params, K, L2, proof)


#####################################################
# TASK 4 -- Prove correct encryption and knowledge of 
#           a plaintext.

@pytest.mark.task4
def test_prove_enc_correct():
    params = setup()

    priv, pub = key_gen(params)

    k, ciphertext = encrypt(params, pub, 10)
    proof = prove_enc(params, pub, ciphertext, k, 10)
    assert verify_enc(params, pub, ciphertext, proof)


@pytest.mark.task4
def test_prove_enc_incorrect():
    params = setup()

    priv, pub = key_gen(params)

    k, ciphertext = encrypt(params, pub, 10)
    _, ciphertext2 = encrypt(params, pub, 20)

    proof = prove_enc(params, pub, ciphertext, k, 10)
    assert not verify_enc(params, pub, ciphertext2, proof)


#####################################################
# TASK 5 -- Prove a linear relation
#

@pytest.mark.task5
def test_prove_rel_correct():
    params = setup()
    C, x0, x1, r = relation(params, 20)
    proof = prove_x0eq10x1plus20(params, C, x0, x1, r)
    assert verify_x0eq10x1plus20(params, C, proof)


@pytest.mark.task5
def test_prove_rel_incorrect():
    params = setup()
    C, x0, x1, r = relation(params, 20)
    proof = prove_x0eq10x1plus20(params, C, x1, x0, r)
    assert not verify_x0eq10x1plus20(params, C, proof)
