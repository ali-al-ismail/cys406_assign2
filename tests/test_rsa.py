"""RSA tests."""
from cys406_assign2.crypto.rsa import RSA


def test_miller_rabin() -> None:
    """Test the Miller-Rabin primality test."""
    assert RSA._miller_rabin(2, 5)
    assert RSA._miller_rabin(3, 5)
    assert not RSA._miller_rabin(6, 5)
    assert not RSA._miller_rabin(100, 5)
    assert RSA._miller_rabin(101, 5)
    assert RSA._miller_rabin(1009, 5)
    assert not RSA._miller_rabin(10006, 5)
    assert RSA._miller_rabin(10007, 5)


def test_generate_prime() -> None:
    """Test the prime number generation."""
    prime = RSA._generate_prime(512)
    print()
    print(f"Generated prime: {prime}")

def test_keygen() -> None:
    """Test the RSA key generation."""
    public_key, private_key = RSA.generate_keys()
    rsa = RSA(public_key, private_key)
    assert rsa.public is not None
    assert rsa.private is not None
    assert rsa.public.n == rsa.private.n

def test_encrypt_decrypt() -> None:
    """Test the RSA encryption and decryption."""
    public_key, private_key = RSA.generate_keys()
    rsa = RSA(public_key, private_key)


    plaintext = b"Hello"
    ciphertext = rsa.encrypt(plaintext)
    decrypted = rsa.decrypt(ciphertext)
    assert decrypted == plaintext

def test_sign_verify() -> None:
    """Test the RSA signing and verification."""
    public_key, private_key = RSA.generate_keys()
    rsa = RSA(public_key, private_key)
    message = b"Hello"
    signature = rsa.sign(message)
    assert rsa.verify(message, signature)
