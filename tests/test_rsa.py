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


def test_keygen() -> None:
    """Test the RSA key generation."""
    rsa = RSA()
    rsa.generate_keys()
    assert rsa.public is not None
    assert rsa.private is not None
    assert rsa.public.n == rsa.private.n

def test_encrypt_decrypt() -> None:
    """Test the RSA encryption and decryption."""
    rsa = RSA()
    rsa.generate_keys()
    plaintext = b"Hello"
    ciphertext = rsa.encrypt(plaintext)
    decrypted = rsa.decrypt(ciphertext)
    assert decrypted == plaintext

def test_sign_verify() -> None:
    """Test the RSA signing and verification."""
    rsa = RSA()
    rsa.generate_keys()
    message = b"Hello"
    signature = rsa.sign(message)
    assert rsa.verify(message, signature)
