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
from hashlib import sha256
from math import gcd


class PublicKeyError(Exception):
    """Exception raised when the public key is invalid."""

class PrivateKeyError(Exception):
    """Exception raised when the private key is invalid."""

class MessageTooLongError(Exception):
    """Exception raised when the message is too long."""

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
    def _generate_prime(n_bits: int = 512) -> int:
        """
        Generate a random prime number.

        This function generates a random prime number of n_bits length
        using the Miller-Rabin primality test. It first generates a random
        number of n_bits length and checks if it's divisible by any of the
        small primes. If it is, it continues to generate a new number.
        If it's not, it checks if the number is prime using the Miller-Rabin

        Args:
            n_bits (int): Number of bits for the prime number. Defaults to 2048.

        Returns:
            int: A random prime number.

        """
        small_primes = [
            2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43,
            47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
            101, 103, 107, 109, 113, 127, 131, 137, 139, 149
            ]
        while True:
            num = secrets.randbits(n_bits)
            if any(num % p == 0 for p in small_primes):
                continue
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

    @staticmethod
    def generate_keys(
        size: int = 512,
        e: int = 65537) -> tuple[
        PublicKey, PrivateKey
        ]:
        """Generate an RSA key pair."""
        if e < 3:
            msg = "Public exponent must be at least 3."
            raise ValueError(msg)
        count = 0

        while True:
            count += 1
            p = RSA._generate_prime(size)
            q = RSA._generate_prime(size)

            if count > 20:
                msg = "Failed to generate key, try a different exponent."
                raise ValueError(msg)

            if p == q:
                continue
            if gcd(e, (p - 1) * (q - 1)) == 1:
                break

        n = p * q
        phi = (p - 1) * (q - 1)

        d = pow(e, -1, phi)
        return PublicKey(n, e), PrivateKey(n, d)

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt the plaintext using the public key.

        Args:
            plaintext (bytes): The plaintext to encrypt.

        Returns:
            bytes: The encrypted ciphertext.

        """
        if self.public is None:
            msg = "Public key is not set."
            raise PublicKeyError(msg)

        p_int = int.from_bytes(plaintext, "big")
        if p_int >= self.public.n:
            msg = "Message is too long for the public key."
            raise MessageTooLongError(msg)
        c_int = pow(p_int, self.public.e, self.public.n)
        return c_int.to_bytes((c_int.bit_length() + 7) // 8, "big")

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt the ciphertext using the private key.

        Args:
            ciphertext (bytes): The ciphertext to decrypt.

        Returns:
                str: The decrypted plaintext.

        """
        if self.private is None:
            msg = "Private key is not set."
            raise PrivateKeyError(msg)
        c_int = int.from_bytes(ciphertext, "big")
        if c_int >= self.private.n:
            msg = "Ciphertext is too long for the private key."
            raise MessageTooLongError(msg)
        p_int = pow(c_int, self.private.d, self.private.n)
        return p_int.to_bytes((p_int.bit_length() + 7) // 8, "big")

    def sign(self, message: bytes) -> bytes:
        """
        Sign the message using the private key.

        Args:
            message (bytes): The message to sign.

        Returns:
            bytes: The signature.

        """
        if self.private is None:
            msg = "Private key is not set."
            raise PrivateKeyError(msg)

        h = sha256(message).digest()
        h_int = int.from_bytes(h, "big")

        if h_int >= self.private.n:
            msg = "Message is too long for the private key."
            raise MessageTooLongError(msg)

        s_int = pow(h_int, self.private.d, self.private.n)
        return s_int.to_bytes((s_int.bit_length() + 7) // 8, "big")

    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Verify the signature of the message using the public key.

        Args:
            message (bytes): The message to verify.
            signature (bytes): The signature to verify.

        Returns:
            bool: True if the signature is valid, False otherwise.

        """
        if self.public is None:
            msg = "Public key is not set."
            raise PublicKeyError(msg)
        s_int = int.from_bytes(signature, "big")
        if s_int >= self.public.n:
            msg = "Signature is too long for the public key."
            raise MessageTooLongError(msg)
        h_int = pow(s_int, self.public.e, self.public.n)
        h = h_int.to_bytes((h_int.bit_length() + 7) // 8, "big")
        return sha256(message).digest() == h
