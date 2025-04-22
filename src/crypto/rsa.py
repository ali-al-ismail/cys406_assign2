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
