from dataclasses import dataclass

Point = tuple[int, int] | None


@dataclass(frozen=True)
class CurveParameters:
	p: int
	a: int
	b: int
	g: Point
	n: int

# Default EC curve will be secp256k1.
SECP256K1 = CurveParameters(
	p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
	a=0,
	b=7,
	g=(
		0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
		0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
	),
	n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
)


class EllipticCurveMath:
	def __init__(self, curve: CurveParameters):
		if curve is None:
			raise ValueError('Curve is required')
		self.curve = curve
		self._validate_curve()

	def is_on_curve(self, point: Point) -> bool:
		if point is None:
			return True

		x, y = point
		left = (y * y) % self.curve.p
		right = (pow(x, 3, self.curve.p) + self.curve.a * x + self.curve.b) % self.curve.p
		return left == right

	def point_add(self, p1: Point, p2: Point) -> Point:
		if p1 is None:
			return p2
		if p2 is None:
			return p1

		x1, y1 = p1
		x2, y2 = p2

		if x1 == x2 and (y1 + y2) % self.curve.p == 0:
			return None

		if p1 == p2:
			return self.point_double(p1)

		slope = ((y2 - y1) * self._mod_inverse(x2 - x1, self.curve.p)) % self.curve.p
		x3 = (slope * slope - x1 - x2) % self.curve.p
		y3 = (slope * (x1 - x3) - y1) % self.curve.p
		return x3, y3

	def point_double(self, point: Point) -> Point:
		if point is None:
			return None

		x1, y1 = point
		if y1 == 0:
			return None

		slope = ((3 * x1 * x1 + self.curve.a) * self._mod_inverse(2 * y1, self.curve.p)) % self.curve.p
		x3 = (slope * slope - 2 * x1) % self.curve.p
		y3 = (slope * (x1 - x3) - y1) % self.curve.p
		return x3, y3

	def scalar_mult(self, k: int, point: Point) -> Point:
		if point is None:
			return None
		if k % self.curve.n == 0:
			return None

		self._validate_point(point)

		result: Point = None
		addend = point
		scalar = k

		while scalar > 0:
			if scalar & 1:
				result = self.point_add(result, addend)
			addend = self.point_double(addend)
			scalar >>= 1

		return result

	def _validate_curve(self) -> None:
		if not self.is_on_curve(self.curve.g):
			raise ValueError('Base point is not on the curve')
		if self.scalar_mult(self.curve.n, self.curve.g) is not None:
			raise ValueError('Base point does not have the expected order')

	def _validate_point(self, point: Point) -> None:
		if point is None:
			return
		if not self.is_on_curve(point):
			raise ValueError('Point is not on the curve')

	@staticmethod
	def _mod_inverse(value: int, modulus: int) -> int:
		value %= modulus
		if value == 0:
			raise ZeroDivisionError('Inverse does not exist')
		return pow(value, -1, modulus)