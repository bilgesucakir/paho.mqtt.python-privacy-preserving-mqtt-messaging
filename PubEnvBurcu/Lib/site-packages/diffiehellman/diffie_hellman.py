#  Copyright (c) Kuba Szczodrzyński 2021-5-6.

import os

from .primes import PRIMES


class DiffieHellman:
    _prime: int
    _private_key: int
    _public_key: int
    _shared_key: int

    @staticmethod
    def _to_bytes(a: int) -> bytes:
        return a.to_bytes((a.bit_length() + 7) // 8, byteorder="big")

    def __init__(self, group: int = 14, key_bits: int = 540) -> None:
        prime_bytes = PRIMES[group]
        self._prime = int.from_bytes(prime_bytes, byteorder="big")
        self.generate_private_key(key_bits)

    def generate_private_key(self, key_bits: int = 540) -> bytes:
        private_key = os.urandom(key_bits // 8 + 8)
        self.set_private_key(private_key)
        return self.get_private_key()

    def set_private_key(self, key: bytes) -> None:
        self._private_key = int.from_bytes(key, byteorder="big")
        self._public_key = pow(2, self._private_key, self._prime)

    def generate_shared_key(self, other_public_key: bytes) -> bytes:
        remote_key = int.from_bytes(other_public_key, "big")
        self._shared_key = pow(remote_key, self._private_key, self._prime)
        return self.get_shared_key()

    def get_private_key(self) -> bytes:
        return self._to_bytes(self._private_key)

    def get_public_key(self) -> bytes:
        return self._to_bytes(self._public_key)

    def get_shared_key(self) -> bytes:
        return self._to_bytes(self._shared_key)
