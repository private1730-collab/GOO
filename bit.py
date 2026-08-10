import requests
import ecdsa
from ecdsa import SECP256k1, SigningKey, VerifyingKey, NumberCurve
import hashlib
import sys

# --- CONFIGURATION ---
# Change these variables to test different addresses
NETWORK = "testnet"  # Options: "mainnet" or "testnet"
ADDRESS = "mzBc4X...YOUR_ADDRESS_HERE" # Replace with your target Bitcoin Address

# API Endpoint (BlockCypher)
if NETWORK == "mainnet":
    BASE_URL = f"https://api.blockcypher.com/v1/btc/main/addrs/{ADDRESS}/txs?limit=50"
else:
    BASE_URL = f"https://api.blockcypher.com/v1/btc/test3/addrs/{ADDRESS}/txs?limit=50"

# --- HELPER FUNCTIONS ---

def hex_to_int(hex_str):
    """Converts a hex string to an integer."""
    if hex_str.startswith("0x"):
        return int(hex_str, 16)
    return int(hex_str, 16)

def get_transactions(address_url):
    """Fetches transactions for the given address."""
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

def base58_decode(base58_string):
    """Decodes a Base58 string to bytes."""
    ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = 0
    for char in base58_string:
        num = num * 58 + ALPHABET.index(char)
    
    # Convert to bytes
    length = (num.bit_length() + 7) // 8
    return num.to_bytes(length, byteorder='big')

def base58_encode(payload):
    """Encodes bytes to Base58 string."""
    ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(payload, byteorder='big')
    encoded = ''
    while num > 0:
        num, remainder = divmod(num, 58)
        encoded = ALPHABET[remainder] + encoded
    
    # Add leading '1's for each leading zero byte in the payload
    for byte in payload:
        if byte == 0:
            encoded = '1' + encoded
        else:
            break
    return encoded

def derive_address_from_private_key(private_key_int, network):
    """
    Derives the Bitcoin address from a private key.
    """
    # 1. Create the Public Key from Private Key
    sk = SigningKey.from_secret_exponent(private_key_int, curve=SECP256k1)
    pk = sk.get_verifying_key()
    
    # 2. Get Public Key Hex (Compressed or Uncompressed? We'll try Uncompressed first, then Compressed)
    # Bitcoin addresses can be from either. We'll check both.
    
    # Uncompressed Public Key
    pk_uncompressed = pk.to_string()  # 65 bytes: 0x04 + X + Y
    # Compressed Public Key
    pk_compressed = pk.get_compressed_bytes()  # 33 bytes: 0x02/0x03 + X + Y
    
    def get_p2pkh_address(pub_key_bytes):
        # Step A: SHA256
        sha256_hash = hashlib.sha256(pub_key_bytes).digest()
        # Step B: RIPEMD160
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
        
        # Step C: Add Version Byte
        if network == "mainnet":
            version_byte = b'\x00'  # Mainnet P2PKH starts with 1
        else:
            version_byte = b'\x6F'  # Testnet P2PKH starts with m or n
        
        payload = version_byte + ripemd160_hash
        
        # Step D: Double SHA256 for Checksum
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        
        # Step E: Combine and Convert to Base58
        address_bytes = payload + checksum
        return base58_encode(address_bytes)

    # Try both uncompressed and compressed
    addr_uncompressed = get_p2pkh_address(pk_uncompressed)
    addr_compressed = get_p2pkh_address(pk_compressed)
    
    return [addr_uncompressed, addr_compressed]

def verify_signature_with_private_key(private_key_int, r, s, msg_hash_int):
    """
    Verifies if the private key produces the correct signature (r, s) for the message.
    """
    try:
        sk = SigningKey.from_secret_exponent(private_key_int, curve=SECP256k1)
        vk = sk.get_verifying_key()
        
        # Verify signature
        # ecdsa library expects the signature as a combined bytes object or separate r, s
        # We will use the low-level verify
        # Note: ecdsa.VerifyingKey.verify_sig expects an ecdsa.Signature object
        sig = ecdsa.Signature(r, s)
        return vk.verify_sig(sig, msg_hash_int, hashfunc=None)
    except Exception:
        return False

# --- MAIN LOGIC ---

def brute_force_nonce_and_solve():
    print(f"Analyzing address: {ADDRESS} ({NETWORK})")
    print("Note: This script looks for REPEATED NONCES (k) in two different transactions.")
    print("If no repeated nonces are found, the private key cannot be derived without knowing 'k'.")
    print("-" * 50)
    
    txs = get_transactions(BASE_URL)
    
    if not txs:
        print("No transactions found.")
        return

    signatures = []
    
    for tx in txs:
        tx_hash = tx['hash']
        # BlockCypher provides input details in 'vin'
        for vin in tx['vin']:
            # We need the scriptSig (the raw input script) to extract r and s
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
                if len(sig_bytes) < 4:
                    continue
                r_len = sig_bytes[3]
                if 4 + r_len > len(sig_bytes):
                    continue
                r_bytes = sig_bytes[4:4+r_len]
                
                # Parse S
                s_offset = 4 + r_len
                if s_offset + 1 > len(sig_bytes):
                    continue
                s_len = sig_bytes[s_offset]
                if s_offset + 1 + s_len > len(sig_bytes):
                    continue
                s_bytes = sig_bytes[s_offset+1:s_offset+1+s_len]
                
                # Convert R and S to integers
                r = int.from_bytes(r_bytes, byteorder='big')
                s = int.from_bytes(s_bytes, byteorder='big')
                
                # Get Message Hash (Double SHA256 of the transaction)
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
                
                # Verify Signature
                if verify_signature_with_private_key(d, sig1['r'], sig1['s'], sig1['msg_hash']):
                    print("SUCCESS: Private Key Matches the Signature!")
                    
                    # Derive Address
                    derived_addresses = derive_address_from_private_key(d, NETWORK)
                    
                    print("Derived Addresses:")
                    for addr in derived_addresses:
                        print(f"  - {addr}")
                        
                    if ADDRESS in derived_addresses:
                        print("\nCONGRATULATIONS! The Private Key MATCHES the Input Address!")
                    else:
                        print("\nPrivate Key is valid for the transaction, but might be for a different address (e.g., Compressed vs Uncompressed mismatch).")
                        
                else:
                    print("Verification Failed.")
                    
            except ZeroDivisionError:
                print("Error: S1 and S2 are identical, or other math error.")
            except Exception as e:
                print(f"Math Error: {e}")
            
            return # Found one, let's stop.
        else:
            r_map[r] = {'sig': sig, 'tx_hash': sig['tx_hash']}
    
    print("\nNo repeated nonces found in the checked transactions.")
    print("The private key cannot be extracted without knowing 'k' or having a side-channel leak.")

if __name__ == "__main__":
    # If you want to pass address via command line:
    if len(sys.argv) > 1:
        ADDRESS = sys.argv[1]
        # Detect network from address prefix
        if ADDRESS.startswith('m') or ADDRESS.startswith('n'):
            NETWORK = "testnet"
        elif ADDRESS.startswith('1'):
            NETWORK = "mainnet"
        else:
            print("Assuming Testnet. Change NETWORK variable if needed.")
            
    brute_force_nonce_and_solve()
