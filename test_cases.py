#!/usr/bin/env python3
"""
Comprehensive Test Suite for Cryptographic Implementations
Covers: AES, SHA256, Elliptic Curve Asymmetric Encryption, and Schnorr Digital Signature
"""

import hashlib
from aes import AES
from sha256 import SHA256
from ec_asymmetric import ECCAsymmetricEncryption
from eccdh import ECCDH
from ecc_math import CurveParameters, EllipticCurveMath, SECP256K1
from schnorr_digital_signature import SchnorrDigitalSignature

# Try to import standard cryptography libraries for verification
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print("Note: cryptography library not installed for AES verification")


# ============================================================================
# TEST 1: AES Encryption/Decryption
# ============================================================================
def test_aes():
    print("\nTEST 1: AES ENCRYPTION/DECRYPTION\n")
    
    plaintext = "DaiHocGiaoThongVanTaiTPHCM"
    key = "LeHuynhAnhKhoi24"  # 24 characters = 192 bits (AES-192)
    
    print(f"Plaintext: {plaintext}")
    print(f"Key: {key}")
    print(f"Key length: {len(key)} bytes ({len(key) * 8} bits)\n")
    
    # Test ECB mode
    print("ECB Mode:")
    aes_ecb = AES(key, mode='ecb')
    ciphertext_ecb = aes_ecb.encrypt(plaintext)
    decrypted_ecb = aes_ecb.decrypt(ciphertext_ecb)
    
    print(f"  Key: {key}")
    print(f"  Ciphertext (hex): {ciphertext_ecb}")
    print(f"  Decryption OK: {decrypted_ecb == plaintext}\n")
    
    # Verify with cryptography library (ECB fixed plaintext)
    if HAS_CRYPTO:
        print("Verification with cryptography library:")
        test_pt = "ABCDEFGHIJKLMNOP"  # 16 bytes for single block
        test_key = "0123456789ABCDEF"  # 16 bytes = 128 bits
        
        # ECB Mode
        print("  ECB Mode:")
        aes_custom = AES(test_key, mode='ecb')
        ct_custom = aes_custom.encrypt(test_pt)
        
        cipher = Cipher(algorithms.AES(test_key.encode()), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        ct_std = encryptor.update(test_pt.encode()) + encryptor.finalize()
        ct_std_hex = ct_std.hex()
        
        print(f"    Test key: {test_key}")
        print(f"    Custom ciphertext:   {ct_custom}")
        print(f"    Standard ciphertext: {ct_std_hex}")
        print(f"    ECB Match: {ct_custom == ct_std_hex}")
        
        # CBC Mode with fixed IV
        print("  CBC Mode (fixed IV):")
        test_iv = "FEDCBA9876543210"  # 16 bytes = 128 bits
        
        aes_cbc_custom = AES(test_key, mode='cbc', iv=test_iv.encode())
        ct_cbc_custom = aes_cbc_custom.encrypt(test_pt)
        
        cipher_cbc = Cipher(algorithms.AES(test_key.encode()), modes.CBC(test_iv.encode()), backend=default_backend())
        encryptor_cbc = cipher_cbc.encryptor()
        ct_cbc_std = encryptor_cbc.update(test_pt.encode()) + encryptor_cbc.finalize()
        ct_cbc_std_hex = ct_cbc_std.hex()
        
        print(f"    Test key: {test_key}")
        print(f"    Test IV: {test_iv}")
        print(f"    Custom ciphertext:   {ct_cbc_custom[32:]}")
        print(f"    Standard ciphertext: {ct_cbc_std_hex}")
        print(f"    CBC Match: {ct_cbc_custom[32:] == ct_cbc_std_hex}")
    
    # Test CBC mode
    print("CBC Mode (Auto IV):")
    aes_cbc = AES(key, mode='cbc')
    ciphertext_cbc = aes_cbc.encrypt(plaintext)
    decrypted_cbc = aes_cbc.decrypt(ciphertext_cbc)
    
    print(f"  Key: {key}")
    print(f"  IV (hex): {aes_cbc.iv.hex()}")
    print(f"  Ciphertext (hex): {ciphertext_cbc}")
    print(f"  Decryption OK (CBC auto IV): {decrypted_cbc == plaintext}")


# ============================================================================
# TEST 2: SHA256 Hash Function
# ============================================================================
def test_sha256():
    print("\nTEST 2: SHA256 HASH FUNCTION\n")
    
    # Test with fixed vectors (known answer tests)
    test_vectors = [
        ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),  # empty string
        ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ("LeHuynhAnhKhoiUTHDL24", None),  # compute and show
        ("LeHuynhAnhKHoiUTH_DL24", None),  # compute and show
    ]
    
    print("Fixed Test Vectors (KAT):")
    all_match = True
    for msg, expected in test_vectors:
        custom_hash = SHA256(msg).generating_hash()
        standard_hash = hashlib.sha256(msg.encode()).hexdigest()
        match = custom_hash == standard_hash
        all_match = all_match and match
        display_msg = msg if msg else "(empty string)"
        if expected:
            expected_match = custom_hash == expected
        else:
            expected_match = None
        print(f"  Input: {display_msg} | Custom==Standard: {match} | MatchWithKAT: {expected_match}")

    print(f"All implementations match standard: {all_match}")


# ============================================================================
# TEST 3: Elliptic Curve Asymmetric Encryption (Alice & Bob)
# ============================================================================
def test_elliptic_curve_asymmetric():
    print("\nTEST 3: ELLIPTIC CURVE ASYMMETRIC ENCRYPTION (Alice & Bob)\n")
    
    message = "Toi_la_sinh_vien_nam_2_UTH"
    
    print(f"Message: {message}")
    print(f"Message length: {len(message)} bytes")
    print(f"Message hash (SHA256): {hashlib.sha256(message.encode()).hexdigest()}\n")
    
    # Alice and Bob initialize their keys
    print("Key Generation:")
    alice = ECCAsymmetricEncryption()
    bob = ECCAsymmetricEncryption()
    
    alice_private, alice_public = alice.gen_key_pair()
    bob_private, bob_public = bob.gen_key_pair()
    
    print(f"  Alice Private (hex): {hex(alice_private)}")
    print(f"  Alice Public X (hex): {hex(alice_public[0])}")
    print(f"  Alice Public Y (hex): {hex(alice_public[1])}\n")
    print(f"  Bob Private (hex): {hex(bob_private)}")
    print(f"  Bob Public X (hex): {hex(bob_public[0])}")
    print(f"  Bob Public Y (hex): {hex(bob_public[1])}\n")
    
    # Alice encrypts message for Bob
    print("Alice Encrypts for Bob:")
    payload = alice.encrypt(message, bob_public)
    
    print(f"  Ephemeral Public Key X (hex): {hex(payload['sender_public_key'][0])}")
    print(f"  Ephemeral Public Key Y (hex): {hex(payload['sender_public_key'][1])}")
    print(f"  Plaintext Hash: {payload['plaintext_hash']}")
    
    # Bob decrypts message
    print("Bob Decrypts:")
    decrypted_message = bob.decrypt(payload)
    
    print(f"  Decrypted: {decrypted_message}")
    print(f"  Decryption OK: {decrypted_message == message}\n")
        
# ============================================================================
# TEST 4: Schnorr Digital Signature
# ============================================================================
def test_schnorr_signature():
    print("\nTEST 4: SCHNORR DIGITAL SIGNATURE\n")
    
    message = "LeHuynhAnhKhoi_UTH_DL24"
    
    print(f"Message: {message}")    
    # Initialize Schnorr signature scheme
    print("System Parameter Generation:")
    schnorr = SchnorrDigitalSignature()
    print("  Generating p, q, a...")
    p, q, a = schnorr._generate_parameters(p_bits=512, q_bits=160)
    schnorr.p = p
    schnorr.q = q
    schnorr.a = a
        
    # Generate key pair
    print("Key Pair Generation:")
    private_key, public_key = schnorr.gen_key_pair()
    print(f"  Private s (hex): {hex(private_key)}")
    print(f"  Public v = a^(-s) mod p (hex): {hex(public_key)}")
    print(f"  Public key in range (1, p): {1 < public_key < p}\n")
    
    # Sign message
    print("Message Signing:")
    e, y = schnorr.sign(message, private_key)
    print(f"  Signature e (challenge, hex): {hex(e)}")
    print(f"  Signature y (response, hex): {hex(y)}")
    # Verify signature
    print("Signature Verification:")
    is_valid = schnorr.verify(message, (e, y), public_key)
    print(f"  Valid: {is_valid}\n")

    # Test invalid cases
    print("Invalid Case 1: Tampered Message")
    tampered_message = "LeHuynhAnhKhoi_UTH_DL25"
    tampered_valid = schnorr.verify(tampered_message, (e, y), public_key)
    print(f"  Original: {message}")
    print(f"  Tampered: {tampered_message}")
    print(f"  Signature Valid: {tampered_valid} (should be False)\n")
    
    print("Invalid Case 2: Wrong Public Key")
    wrong_public = (public_key + 1) % schnorr.p
    wrong_valid = schnorr.verify(message, (e, y), wrong_public)
    print(f"  Original public (hex): {hex(public_key)[:50]}...")
    print(f"  Wrong public (hex): {hex(wrong_public)[:50]}...")
    print(f"  Signature Valid: {wrong_valid} (should be False)\n")
    
    print("Invalid Case 3: Corrupted Signature (e)")
    corrupted_e = (e + 1) % schnorr.q
    corrupted_valid = schnorr.verify(message, (corrupted_e, y), public_key)
    print(f"  Original e (hex): {hex(e)}")
    print(f"  Corrupted e (hex): {hex(corrupted_e)}")
    print(f"  Signature Valid: {corrupted_valid} (should be False)\n")
    
    print("Invalid Case 4: Corrupted Signature (y)")
    corrupted_y = (y + 1) % schnorr.q
    corrupted_valid_y = schnorr.verify(message, (e, corrupted_y), public_key)
    print(f"  Original y (hex): {hex(y)}")
    print(f"  Corrupted y (hex): {hex(corrupted_y)}")
    print(f"  Signature Valid: {corrupted_valid_y} (should be False)")


# ============================================================================
# MAIN
# ============================================================================
def print_menu():
    print("\n" + "="*60)
    print("CRYPTOGRAPHIC TEST SUITE")
    print("="*60)
    print("\nSelect a test to run:")
    print("  1) AES Encryption/Decryption")
    print("  2) SHA256 Hash Function")
    print("  3) Elliptic Curve Asymmetric Encryption (Alice & Bob)")
    print("  4) Schnorr Digital Signature")
    print("  5) Run all tests")
    print("  0) Exit")
    print("-"*60)


if __name__ == "__main__":
    while True:
        print_menu()
        choice = input("Enter your choice (0-5): ").strip()
        
        try:
            if choice == '0':
                print("Exiting...\n")
                break
            elif choice == '1':
                test_aes()
            elif choice == '2':
                test_sha256()
            elif choice == '3':
                test_elliptic_curve_asymmetric()
            elif choice == '4':
                test_schnorr_signature()
            elif choice == '5':
                test_aes()
                test_sha256()
                test_elliptic_curve_asymmetric()
                test_schnorr_signature()
                print("\n" + "="*60)
                print("ALL TESTS COMPLETED")
                print("="*60 + "\n")
            else:
                print("Invalid choice. Please try again.")
        except Exception as e:
            print(f"\nERROR: {e}")
            import traceback
            traceback.print_exc()
