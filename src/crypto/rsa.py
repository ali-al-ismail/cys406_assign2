"""RSA encryption and decryption module."""

###############################################################
# Goals:
# - Generate two prime numbers p and q at least 3 digits long
# - Miller Rabin primality test
# - Generate n, e, d
# - encryption and decryption logic
# - digital signature signing and verification
###############################################################

import secrets
from dataclasses import dataclass
from math import gcd


@dataclass
class PublicKey:
    """Public key class."""

    n: int
    e: int

@dataclass
class PrivateKey:
    """Private key class."""

    n: int
    d: int


class RSA:
    """RSA encryption and decryption class."""

    def __init__(
            self, public: PublicKey | None = None, private: PrivateKey | None = None
            ) -> None:
        """
        Initialize the RSA class.

        Args:
            public (PublicKey, optional): Public key. Defaults to None.
            private (PrivateKey, optional): Private key. Defaults to None.

        """
        self.public = public
        self.private = private

    @staticmethod
    def _generate_prime() -> int:
        """Generate a random prime number."""
        while True:
            num = secrets.randbelow(99999999999999) + 1000000
            if RSA._miller_rabin(num, 20):
                return num


    @staticmethod
    def _miller_rabin(n: int, acc: int) -> bool:
        """
        Miller-Rabin primality test.

        Args:
            n (int): Number to test for primality.
            acc (int): Number of iterations.

        Returns:
            bool: True if n is prime, False otherwise.

        """
        if n <= 1:
            return False
        if n <= 3:  # noqa: PLR2004
            return True
        if n % 2 == 0:
            return False
        r = 0
        d = n - 1
        while d % 2 == 0:
            d //= 2
            r += 1

        for _ in range(acc):
            a = secrets.randbelow(n - 4) + 2
            x = pow(a, d, n)

            if x == 1 or x == n - 1:
                continue

            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False

        return True



    def generate_keys(self) -> None:
        """Generate an RSA key pair."""
        p = self._generate_prime()
        q = self._generate_prime()
        while q == p:
            q = self._generate_prime()

        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        while gcd(e, phi) != 1 or e >= phi:
            e = secrets.randbelow(phi - 1) + 3

        d = pow(e, -1, phi)
        self.public = PublicKey(n, e)
        self.private = PrivateKey(n, d)

    def encrypt(self, plaintext: str, public_key: PublicKey) -> str:
        """
        Encrypt the plaintext using the public key.

        Args:
            plaintext (str): The plaintext to encrypt.
            public_key (PublicKey): The public key to use for encryption.

        Returns:
            str: The encrypted ciphertext.

        """
        return ""

    def decrypt(self, ciphertext: str, private_key: PrivateKey) -> str:
        """Decrypt the ciphertext using the private key."""
        return ""

