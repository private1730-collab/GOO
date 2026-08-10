import requests
import ecdsa
from ecdsa import SECP256k1, NumberCurve
import hashlib

# --- CONFIGURATION ---
# 1. Choose your Bitcoin Network
NETWORK = "testnet"  # Change to "mainnet" for Bitcoin Main
ADDRESS = "mtWHP4G87x4t6S1FjJbU5jJ5J5J5J5J5J5" # Replace with your target address
# Example Testnet Address: mtWHP4G87x4t6S1FjJbU5jJ5J5J5J5J5J5 (This is a placeholder)
# For testing, you can use a known address with a repeated nonce.

# 2. API Endpoint (BlockCypher)
if NETWORK == "mainnet":
    BASE_URL = f"https://api.blockcypher.com/v1/btc/main/addrs/{ADDRESS}/txs"
else:
    BASE_URL = f"https://api.blockcypher.com/v1/btc/test3/addrs/{ADDRESS}/txs"

# --- HELPER FUNCTIONS ---

def hex_to_int(hex_str):
    """Converts a hex string to an integer."""
    if hex_str.startswith("0x"):
        return int(hex_str, 16)
    return int(hex_str, 16)

def get_transactions(address_url):
    """Fetches the first 20 transactions for the given address."""
    try:
        response = requests.get(address_url, timeout=10)
        data = response.json()
        if 'txs' in data:
            return data['txs']
        else:
            print(f"Error fetching transactions: {data.get('message', 'Unknown error')}")
            return []
    except Exception as e:
        print(f"Network Error: {e}")
        return []

def calculate_private_key(r, s, msg_hash_int, nonce_k):
    """
    Calculates the private key 'd' using the ECDSA formula:
    s = k^-1 * (H(m) + r*d) mod n
    Rearranged: d = (s*k - H(m)) * r^-1 mod n
    """
    n = SECP256k1.order
    
    # Calculate modular inverse of r
    r_inv = pow(r, n - 2, n)
    
    # Calculate private key d
    d = ((s * nonce_k - msg_hash_int) * r_inv) % n
    
    return d

def verify_private_key(private_key_int, target_address):
    """
    Verifies if the calculated private key corresponds to the target address.
    """
    # 1. Create the Public Key from Private Key
    sk = ecdsa.SigningKey.from_secret_exponent(private_key_int, curve=SECP256k1)
    pk = sk.get_verifying_key()
    
    # 2. Get Public Key Hex
    pk_hex = pk.to_string().hex()
    
    # 3. Derive Bitcoin Address from Public Key
    # Step A: SHA256
    sha256_hash = hashlib.sha256(bytes.fromhex(pk_hex)).digest()
    # Step B: RIPEMD160
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    
    # Step C: Add Version Byte (0x00 for Mainnet, 0x6F for Testnet)
    version_byte = b'\x00' if NETWORK == "mainnet" else b'\x6F'
    payload = version_byte + ripemd160_hash
    
    # Step D: Double SHA256 for Checksum
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    
    # Step E: Combine and Convert to Base58
    address_bytes = payload + checksum
    
    # Simple Base58 Encoding
    ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(address_bytes, byteorder='big')
    encoded = ''
    while num > 0:
        num, remainder = divmod(num, 58)
        encoded = ALPHABET[remainder] + encoded
    
    # Add leading '1's for leading zero bytes in payload
    leading_zeros = len(version_byte) - len(payload.lstrip(b'\x00'))
    # Actually, for standard P2PKH, the version byte is the first byte.
    # If the first byte is 0x00, we add '1's equal to the number of leading zeros in the payload.
    for _ in range(len(version_byte)): # Simplified for version byte 0x00
        if payload[0] == 0x00:
            encoded = '1' + encoded
        elif payload[0] == 0x6F:
            encoded = 'm' + encoded # Testnet starts with m or n
            break # Only one leading zero byte for standard testnet P2PKH usually
            
    # Note: This is a simplified Base58 check. For production, use `bitcoin-utils` or `pycoin`.
    # However, for this script, we will compare the RIPEMD160 hash directly to avoid Base58 complexity.
    
    # Better Verification: Compare RIPEMD160 of the target address vs calculated
    # We need to decode the input ADDRESS to get its RIPEMD160
    try:
        # Decode input address to get RIPEMD160
        # This requires reversing the Base58 encoding of the INPUT address
        # Let's use a simpler method: Compare the Public Key Hash directly if possible,
        # or just use a library like `bitcoin` if available. 
        # To keep dependencies low, we will assume the input address is P2PKH.
        
        # Let's use the `ecdsa` library's verification directly on the signature
        # This is more robust than address derivation.
        return None # Placeholder
    except:
        pass

def verify_signature_with_private_key(private_key_int, r, s, msg_hash_int):
    """
    Verifies if the private key produces the correct signature (r, s) for the message.
    """
    try:
        sk = ecdsa.SigningKey.from_secret_exponent(private_key_int, curve=SECP256k1)
        vk = sk.get_verifying_key()
        
        # Verify signature
        # ecdsa library expects the signature as a combined bytes object or separate r, s
        # We will use the low-level verify
        return vk.verify_sig(
            ecdsa.Signature(r, s),
            msg_hash_int,
            hashfunc=None # Since we already have the integer hash
        )
    except Exception:
        return False

# --- MAIN LOGIC ---

def brute_force_nonce_and_solve():
    print(f"Analyzing address: {ADDRESS}")
    print("Note: This script looks for REPEATED NONCES (k) in two different transactions.")
    print("If no repeated nonces are found, the private key cannot be derived without knowing 'k'.")
    print("-" * 50)
    
    txs = get_transactions(BASE_URL)
    
    if not txs:
        print("No transactions found.")
        return

    # Store signatures: key = (r, s), value = {tx_hash, msg_hash}
    # In Bitcoin, we need to extract r and s from the input scripts
    # This is complex because r and s are in the input script (varint length prefixed)
    # For simplicity, we will use BlockCypher's 'vin' details if available, or parse hex.
    
    signatures = []
    
    for tx in txs:
        tx_hash = tx['hash']
        # BlockCypher provides input details in 'vin'
        for vin in tx['vin']:
            # We need the scriptSig (the raw input script) to extract r and s
            # BlockCypher API often includes 'script' in vin
            if 'script' in vin:
                script_hex = vin['script']
                # Parse R and S from the scriptSig
                # Typical P2PKH script: <signature> <public_key>
                # Signature format: <len_sig> <sig_bytes> <len_pk> <pk_bytes>
                
                # Convert hex to bytes
                script_bytes = bytes.fromhex(script_hex)
                
                # Parse length of signature
                if len(script_bytes) < 2:
                    continue
                sig_len = script_bytes[0]
                sig_bytes = script_bytes[1:1+sig_len]
                
                # Signature bytes: <header> <R> <S>
                # Header is usually 0x30
                if sig_bytes[0] != 0x30:
                    continue
                
                # Parse R
                r_len = sig_bytes[3]
                r_bytes = sig_bytes[4:4+r_len]
                
                # Parse S
                s_offset = 4 + r_len
                s_len = sig_bytes[s_offset]
                s_bytes = sig_bytes[s_offset+1:s_offset+1+s_len]
                
                # Convert R and S to integers
                r = int.from_bytes(r_bytes, byteorder='big')
                s = int.from_bytes(s_bytes, byteorder='big')
                
                # Get Message Hash (Double SHA256 of the transaction)
                # Note: In Bitcoin, the message hash is the double SHA256 of the transaction
                # We need to fetch the full transaction hex to calculate this accurately
                # BlockCypher provides 'hash' which is the TxID (reverse hex of double sha256)
                
                # Calculate the message hash integer
                # TxID is in little-endian, so reverse it to get the hash
                tx_id_bytes = bytes.fromhex(tx_hash)
                msg_hash_bytes = tx_id_bytes[::-1] # Reverse to get actual hash
                msg_hash_int = int.from_bytes(msg_hash_bytes, byteorder='big')
                
                signatures.append({
                    'r': r,
                    's': s,
                    'msg_hash': msg_hash_int,
                    'tx_hash': tx_hash
                })
    
    print(f"Extracted {len(signatures)} signatures.")
    
    # Look for repeated R values (Repeated Nonce Attack)
    r_map = {}
    for sig in signatures:
        r = sig['r']
        if r in r_map:
            # Found a repeated R!
            print(f"\n*** FOUND REPEATED NONCE (R) ***")
            print(f"Tx 1: {r_map['tx_hash']}")
            print(f"Tx 2: {sig['tx_hash']}")
            
            sig1 = r_map['sig']
            sig2 = sig
            
            # Calculate k
            n = SECP256k1.order
            # k = (H1 - H2) * (S1 - S2)^-1 mod n
            h1 = sig1['msg_hash']
            h2 = sig2['msg_hash']
            s1 = sig1['s']
            s2 = sig2['s']
            
            try:
                diff_h = (h1 - h2) % n
                diff_s = (s1 - s2) % n
                s_inv = pow(diff_s, n - 2, n)
                k = (diff_h * s_inv) % n
                
                print(f"Calculated Nonce (k): {k}")
                
                # Now calculate private key using one of the signatures
                d = calculate_private_key(sig1['r'], sig1['s'], sig1['msg_hash'], k)
                
                print(f"Calculated Private Key (d): {d}")
                print(f"Private Key (Hex): {hex(d)}")
                
                # Verify
                if verify_signature_with_private_key(d, sig1['r'], sig1['s'], sig1['msg_hash']):
                    print("SUCCESS: Private Key Matches the Signature!")
                    
                    # Final Verification: Does this private key belong to the address?
                    # We do this by deriving the public key and checking the address
                    sk = ecdsa.SigningKey.from_secret_exponent(d, curve=SECP256k1)
                    pk = sk.get_verifying_key()
                    pk_hex = pk.to_string().hex()
                    
                    # Derive Address
                    sha256_hash = hashlib.sha256(bytes.fromhex(pk_hex)).digest()
                    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
                    
                    # Compare with input address
                    # We need to decode the input address to get its RIPEMD160
                    # For simplicity, we'll print the derived address and let you compare
                    # Or we can use a library to decode the input address
                    
                    print("Derived Public Key Hex:", pk_hex)
                    print("Derived RIPEMD160 Hash:", ripemd160_hash.hex())
                    
                    # To fully verify, we need to decode the input ADDRESS
                    # Here is a simple Base58 decode for the input address
                    def base58_decode(base58_string):
                        ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
                        num = 0
                        for char in base58_string:
                            num = num * 58 + ALPHABET.index(char)
                        # Convert to bytes
                        length = (num.bit_length() + 7) // 8
                        return num.to_bytes(length, byteorder='big')
                    
                    try:
                        decoded_bytes = base58_decode(ADDRESS)
                        # Last 4 bytes are checksum, first is version, middle 20 are RIPEMD160
                        input_ripemd160 = decoded_bytes[1:21]
                        
                        if ripemd160_hash == input_ripemd160:
                            print("CONGRATULATIONS! The Private Key MATCHES the Input Address!")
                        else:
                            print("Private Key is valid for the transaction, but might be for a different address in the MultiSig or UTXO set.")
                    except Exception as e:
                        print(f"Error decoding input address: {e}")
                        
                else:
                    print("Verification Failed.")
                    
            except ZeroDivisionError:
                print("Error: S1 and S2 are identical, or other math error.")
            except Exception as e:
                print(f"Math Error: {e}")
            
            return # Found one, let's stop.
        else:
            r_map[r] = {'sig': sig, 'tx_hash': sig['tx_hash']}
    
    print("\nNo repeated nonces found in the first 20 transactions.")
    print("The private key cannot be extracted without knowing 'k' or having a side-channel leak.")

if __name__ == "__main__":
    brute_force_nonce_and_solve()
