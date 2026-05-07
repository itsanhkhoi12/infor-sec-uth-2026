import secrets

from ecc_math import CurveParameters, EllipticCurveMath, Point, SECP256K1

"""Implement key exchange based on EC Diffie-Hellman key agreement protocol
"""

class ECCDH:
	def __init__(self, private_key: int | None = None, curve: CurveParameters | None = None):
		if curve is None:
			curve = SECP256K1
		self.curve = curve
		self.private_key = private_key
		self.public_key: Point = None
		self.math = EllipticCurveMath(curve)

		if self.private_key is not None:
			self._validate_private_key(self.private_key)
			self.public_key = self.math.scalar_mult(self.private_key, self.curve.g)

	def gen_key_pair(self) -> tuple[int, Point]:
		private_key = secrets.randbelow(self.curve.n - 1) + 1
		public_key = self.math.scalar_mult(private_key, self.curve.g)

		self.private_key = private_key
		self.public_key = public_key
		return private_key, public_key

	def derive_shared_secret(self, peer_public_key: Point) -> tuple[int, str]:
		if self.private_key is None:
			raise ValueError('Private key is missing!')

		shared_point = self.math.scalar_mult(self.private_key, peer_public_key)
		if shared_point is None:
			raise ValueError('Shared point is point at infinity!')

		x_coord = shared_point[0]
		x_bytes = x_coord.to_bytes((x_coord.bit_length() + 7) // 8 or 1, 'big')
		return x_coord, x_bytes.hex()

	def _validate_private_key(self, private_key: int) -> None:
		if not (1 <= private_key < self.curve.n):
			raise ValueError('Private key must satisfy 1 <= d < n')


if __name__ == '__main__':
	alice = ECCDH()
	bob = ECCDH()

	alice_private, alice_public = alice.gen_key_pair()
	bob_private, bob_public = bob.gen_key_pair()

	alice_secret = alice.derive_shared_secret(bob_public)
	bob_secret = bob.derive_shared_secret(alice_public)

	print('Alice private:', alice_private)
	print('Bob private:', bob_private)
	print('Alice public:', alice_public)
	print('Bob public:', bob_public)
	print('Alice secret:', alice_secret)
	print('Bob secret:', bob_secret)
	print('Shared secret match:', alice_secret == bob_secret)
