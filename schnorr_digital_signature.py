
import secrets

from sha256 import SHA256

class SchnorrDigitalSignature:
    def __init__(self, p: int = None, q: int = None, a: int = None):
        self.p = p
        self.q = q
        self.a = a

        self.private_key = None
        self.public_key = None

        if self.p is not None or self.q is not None or self.a is not None:
            if self.p is None or self.q is None or self.a is None:
                raise ValueError("p, q, a must be provided together")
            self._validate_parameters(self.p, self.q, self.a)

    def gen_key_pair(self, p_bits: int = 512, q_bits: int = 160) -> tuple[int, int]:
        if self.p is None or self.q is None or self.a is None:
            self.p, self.q, self.a = self._generate_parameters(p_bits=p_bits, q_bits=q_bits)

        s = secrets.randbelow(self.q - 1) + 1
        v = pow(self.a, -s, self.p)

        self.private_key = s
        self.public_key = v
        return s, v

    def sign(self, message: str | bytes, private_key: int = None) -> tuple[int, int]:
        if self.p is None or self.q is None or self.a is None:
            raise ValueError("System parameters are not initialized!")

        s = private_key if private_key is not None else self.private_key
        if s is None:
            raise ValueError("Private key is missing!")
        if not (1 <= s < self.q):
            raise ValueError("Private key must satisfy 0 < s < q")

        message_bytes = self._normalize_message(message)

        r = secrets.randbelow(self.q - 1) + 1
        x = pow(self.a, r, self.p)

        e = self._hash_challenge(message_bytes, x)
        y = (r + (s * e)) % self.q
        return e, y

    def verify(self, message: str | bytes, signature: tuple[int, int], public_key: int = None) -> bool:
        if self.p is None or self.q is None or self.a is None:
            raise ValueError("Global parameters are not initialized!")

        if not isinstance(signature, tuple) or len(signature) != 2:
            return False

        e, y = signature
        if not (0 <= e < self.q and 0 <= y < self.q):
            return False

        v = public_key if public_key is not None else self.public_key
        if v is None:
            raise ValueError("Public key is missing!")
        if not (1 < v < self.p):
            return False

        message_bytes = self._normalize_message(message)

        x_recovered = (pow(self.a, y, self.p) * pow(v, e, self.p)) % self.p
        e_recovered = self._hash_challenge(message_bytes, x_recovered)
        return e_recovered == e

    def _hash_challenge(self, message: bytes, r: int) -> int:
        r_len = (self.p.bit_length() + 7) // 8
        r_bytes = r.to_bytes(r_len, "big")
        digest_hex = SHA256(message + r_bytes).generating_hash()
        return int(digest_hex, 16) % self.q

    @staticmethod
    def _normalize_message(message: str | bytes) -> bytes:
        if isinstance(message, str):
            return message.encode("ascii")
        if isinstance(message, bytes):
            return message
        raise TypeError("Message must be str or bytes")

    @staticmethod
    def _validate_parameters(p: int, q: int, a: int) -> None:
        if p <= 2 or q <= 2:
            raise ValueError("p and q must be prime numbers > 2")
        if (p - 1) % q != 0:
            raise ValueError("q must divide (p - 1)")
        if not (1 < a < p):
            raise ValueError("a must satisfy 1 < a < p")
        if pow(a, q, p) != 1:
            raise ValueError("a must be in subgroup of order q")
        if a == 1:
            raise ValueError("a cannot be 1")

    def _generate_parameters(self, p_bits: int = 512, q_bits: int = 160) -> tuple[int, int, int]:
        if p_bits <= q_bits:
            raise ValueError("p_bits must be larger than q_bits")

        q = self._generate_prime(q_bits)

        min_k = 1 << (p_bits - q_bits - 1)
        max_k = (1 << (p_bits - q_bits)) - 1

        p = None
        for _ in range(20000):
            k = secrets.randbelow(max_k - min_k + 1) + min_k
            candidate_p = k * q + 1

            if candidate_p.bit_length() != p_bits:
                continue
            if self._is_probable_prime(candidate_p):
                p = candidate_p
                break

        if p is None:
            raise RuntimeError("Failed to generate prime p with p = kq + 1")

        exponent = (p - 1) // q
        a = 1
        while a == 1:
            h = secrets.randbelow(p - 3) + 2
            a = pow(h, exponent, p)

        self._validate_parameters(p, q, a)
        return p, q, a

    def _generate_prime(self, bits: int) -> int:
        while True:
            candidate = secrets.randbits(bits)
            candidate |= 1
            candidate |= (1 << (bits - 1))
            if self._is_probable_prime(candidate):
                return candidate

    @staticmethod
    def _is_probable_prime(n: int, rounds: int = 40) -> bool:
        if n < 2:
            return False

        small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
        for prime in small_primes:
            if n == prime:
                return True
            if n % prime == 0:
                return False

        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1

        for _ in range(rounds):
            a = secrets.randbelow(n - 3) + 2
            x = pow(a, d, n)

            if x == 1 or x == n - 1:
                continue

            witness_found = True
            for _ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    witness_found = False
                    break

            if witness_found:
                return False

        return True