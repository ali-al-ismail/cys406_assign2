"""RSA tests."""
from src.crypto.rsa import RSA


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
