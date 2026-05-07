import secrets

from ecc_math import CurveParameters, EllipticCurveMath, Point, SECP256K1
from eccdh import ECCDH
from sha256 import SHA256


class ECCAsymmetricEncryption:
	def __init__(self, private_key: int | None = None, curve: CurveParameters | None = None):
		if curve is None:
			curve = SECP256K1
		self.curve = curve
		self.math = EllipticCurveMath(curve)
		self.private_key = private_key
		self.public_key: Point = None

		if self.private_key is not None:
			self._validate_private_key(self.private_key)
			self.public_key = self.math.scalar_mult(self.private_key, self.curve.g)

		if self.curve.p % 4 != 3:
			raise ValueError('This implementation expects a prime field with p % 4 == 3')

	def gen_key_pair(self) -> tuple[int, Point]:
		key_pair_helper = ECCDH(curve=self.curve)
		private_key, public_key = key_pair_helper.gen_key_pair()
		self.private_key = private_key
		self.public_key = public_key
		return private_key, public_key

	def encrypt(self, plaintext: str | bytes, receiver_public_key: Point) -> dict[str, object]:
		receiver_public_key = self._normalize_point(receiver_public_key)
		plaintext_bytes, encoding = self._normalize_plaintext(plaintext)
		message_hash = SHA256(plaintext_bytes).generating_hash()

		sender_private = secrets.randbelow(self.curve.n - 1) + 1
		sender_public = self.math.scalar_mult(sender_private, self.curve.g)
		shared_point = self.math.scalar_mult(sender_private, receiver_public_key)
		if shared_point is None:
			raise ValueError('Shared point is point at infinity!')

		message_points = self._encode_message_to_points(plaintext_bytes)
		ciphertext_points = [self.math.point_add(message_point, shared_point) for message_point in message_points]

		return {
			'sender_public_key': sender_public,
			'ciphertext_points': ciphertext_points,
			'plaintext_hash': message_hash,
			'encoding': encoding,
		}

	def decrypt(self, payload: dict[str, object]) -> str | bytes:
		if self.private_key is None:
			raise ValueError('Private key is missing!')

		if 'sender_public_key' not in payload or 'ciphertext_points' not in payload:
			raise ValueError('Ciphertext payload is incomplete')

		sender_public_key = self._normalize_point(payload['sender_public_key'])
		encoding = str(payload.get('encoding', 'ascii'))
		ciphertext_points = [self._normalize_point(point) for point in payload['ciphertext_points']]
		expected_hash = str(payload.get('plaintext_hash', ''))

		shared_point = self.math.scalar_mult(self.private_key, sender_public_key)
		if shared_point is None:
			raise ValueError('Shared point is point at infinity!')

		plaintext_bytes = bytearray()
		for ciphertext_point in ciphertext_points:
			message_point = self.math.point_add(ciphertext_point, self._point_negate(shared_point))
			plaintext_bytes.append(self._point_to_byte(message_point))

		actual_hash = SHA256(bytes(plaintext_bytes)).generating_hash()
		if expected_hash and actual_hash != expected_hash:
			raise ValueError('Plaintext checksum mismatch')

		if encoding == 'bytes':
			return plaintext_bytes
		return plaintext_bytes.decode(encoding)

	def _normalize_plaintext(self, plaintext: str | bytes) -> tuple[bytes, str]:
		if isinstance(plaintext, str):
			return plaintext.encode('ascii'), 'ascii'
		return bytes(plaintext), 'bytes'

	def _encode_message_to_points(self, message: bytes) -> list[Point]:
		points = []
		for value in message:
			points.append(self._byte_to_point(value))
		return points

	def _byte_to_point(self, value: int) -> Point:
		base_x = value * 256
		for offset in range(256):
			x_coord = base_x + offset
			if x_coord >= self.curve.p:
				break
			rhs = (pow(x_coord, 3, self.curve.p) + self.curve.a * x_coord + self.curve.b) % self.curve.p
			y_coord = self._sqrt_mod_prime(rhs)
			if y_coord is not None:
				return x_coord, y_coord
		raise ValueError('Unable to encode byte into an elliptic-curve point')

	def _point_to_byte(self, point: Point) -> int:
		if point is None:
			raise ValueError('Invalid message point')
		return point[0] // 256

	def _sqrt_mod_prime(self, value: int) -> int | None:
		if value == 0:
			return 0
		y_coord = pow(value, (self.curve.p + 1) // 4, self.curve.p)
		if (y_coord * y_coord) % self.curve.p != value % self.curve.p:
			return None
		return y_coord

	def _point_negate(self, point: Point) -> Point:
		if point is None:
			return None
		return point[0], (-point[1]) % self.curve.p

	@staticmethod
	def _normalize_point(point: Point | list[int] | tuple[int, int] | None) -> Point:
		if point is None:
			return None
		x_coord, y_coord = point
		return int(x_coord), int(y_coord)

	def _validate_private_key(self, private_key: int) -> None:
		if not (1 <= private_key < self.curve.n):
			raise ValueError('Private key must satisfy 1 <= d < n')
