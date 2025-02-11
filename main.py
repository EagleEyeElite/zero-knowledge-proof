import random

def generate_keypair(g, p):
    """
    Generate a private/public keypair
    g: generator
    p: prime modulus
    returns: (private_key, public_key)
    """
    # Private key (this is the secret we want to prove we know)
    x = random.randint(1, p-2)

    # Public key (publicly known value)
    h = pow(g, x, p)

    return x, h

def prove(g, p, x, h):
    """
    Prover generates proof of knowledge
    g: generator
    p: prime modulus
    x: private key (secret)
    h: public key (h = g^x mod p)
    returns: (commitment, challenge, response)
    """
    # Random value for blinding
    r = random.randint(1, p-2)

    # Commitment (first message)
    commitment = pow(g, r, p)

    # Challenge (would come from verifier in real protocol)
    challenge = random.randint(1, p-2)

    # Response
    response = (r + challenge * x) % (p-1)

    return commitment, challenge, response

def verify(g, p, h, commitment, challenge, response):
    """
    Verifier checks the proof
    returns: True if proof is valid, False otherwise
    """
    # Check if g^response = commitment * h^challenge (mod p)
    left_side = pow(g, response, p)
    right_side = (commitment * pow(h, challenge, p)) % p

    return left_side == right_side

def run_example():
    # Parameters (in practice, use much larger numbers)
    p = 23  # prime modulus
    g = 5   # generator

    # Generate keypair
    private_key, public_key = generate_keypair(g, p)
    print(f"Secret (private key): {private_key}")
    print(f"Public key: {public_key}")

    # Generate and verify proof
    commitment, challenge, response = prove(g, p, private_key, public_key)

    # Verify the proof
    is_valid = verify(g, p, public_key, commitment, challenge, response)
    print(f"\nProof verified: {is_valid}")

    # Important: The verifier learns nothing about x!
    print("\nNote: The verifier only sees:")
    print(f"- Public key (h): {public_key}")
    print(f"- Commitment: {commitment}")
    print(f"- Challenge: {challenge}")
    print(f"- Response: {response}")

def run_multiple_rounds(num_rounds=5):
    """
    Run multiple rounds of the protocol to demonstrate its probabilistic nature
    """
    p = 23
    g = 5

    # Generate real keypair
    real_private_key, real_public_key = generate_keypair(g, p)
    print(f"\nRunning {num_rounds} rounds with real private key...")

    # Test with real private key
    for i in range(num_rounds):
        commitment, challenge, response = prove(g, p, real_private_key, real_public_key)
        is_valid = verify(g, p, real_public_key, commitment, challenge, response)
        print(f"Round {i+1}: {'✓' if is_valid else '✗'}")

    # Test with fake private key (trying to cheat)
    print(f"\nTrying to cheat with fake private key...")
    fake_private_key = real_private_key + 1  # Wrong private key
    for i in range(num_rounds):
        commitment, challenge, response = prove(g, p, fake_private_key, real_public_key)
        is_valid = verify(g, p, real_public_key, commitment, challenge, response)
        print(f"Round {i+1}: {'✓' if is_valid else '✗'}")

if __name__ == "__main__":
    print("=== Basic Zero Knowledge Proof Example ===")
    run_example()

    print("\n=== Multiple Rounds Demonstration ===")
    run_multiple_rounds()

    # Optional: Try with different parameters
    print("\n=== Custom Parameters ===")
    # You can experiment with different prime numbers and generators
    # Note: In practice, use much larger prime numbers (2048 bits or more)
    custom_rounds = 3
    run_multiple_rounds(custom_rounds)
