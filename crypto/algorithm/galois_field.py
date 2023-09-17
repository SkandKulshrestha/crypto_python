# from import external library
from typing import Union, Tuple

# from import internal library
from utility import Utility
from warning_crypto import InvalidComparison


class GaloisField:
    def __init__(self, order: Union[str, int], force=False):
        _order = Utility.convert_to_int(order)

        # do primality test
        if force or Utility.is_prime(_order, 100):
            self.order = _order
        else:
            raise ValueError(f'{_order} is not probable prime')

    def __repr__(self):
        return f"GF({self.order})"

    def __eq__(self, other):
        if isinstance(other, GaloisField):
            return self.order == other.order
        raise InvalidComparison(self, other)

    def __ne__(self, other):
        return not (self == other)

    def set_order(self, order: str):
        self.order = Utility.convert_hex_string_to_int(order)

    def get_order(self) -> str:
        return Utility.convert_int_to_hex_string(self.order)

    def add(self, a: int, b: int) -> int:
        return (a + b) % self.order

    def subtract(self, a: int, b: int) -> int:
        return (a - b) % self.order

    def multiply(self, a: int, b: int) -> int:
        return (a * b) % self.order

    def divide(self, a: int, b: int) -> int:
        b_inv = self.inverse(b)
        return self.multiply(a, b_inv)

    def inverse(self, a: int) -> int:
        # TODO: remove dependency of pow function
        return pow(a, -1, self.order)


class GaloisFieldElement:
    def __init__(self):
        pass


class GaloisFieldTwoPower:
    def __init__(self, polynomial: Union[str, int, Tuple[int, ...]]):
        if isinstance(polynomial, tuple):
            self.polynomial = Utility.create_gf_2_pow_m_polynomial(polynomial)
        else:
            self.polynomial = Utility.convert_to_int(polynomial)

    def add(self, a: int, b: int) -> int:
        return self.polynomial

    def subtract(self, a: int, b: int) -> int:
        return self.polynomial

    def multiply(self, a: int, b: int) -> int:
        return self.polynomial

    def divide(self, a: int, b: int) -> int:
        b_inv = self.inverse(b)
        return self.multiply(a, b_inv)

    def inverse(self, a: int) -> int:
        return self.polynomial


if __name__ == '__main__':
    gf2 = GaloisField(2)
    print(gf2)

    gf11 = GaloisField(11)
    print(gf11)

    _a = 3
    _b = 9

    _c = gf11.add(_a, _b)
    print(f'{_a} + {_b} in {gf11} = {_c}')
    if _c != 1:
        raise ValueError('Addition is not working')

    _c = gf11.subtract(_a, _b)
    print(f'{_a} - {_b} in {gf11} = {_c}')
    if _c != 5:
        raise ValueError('Subtraction is not working')

    _c = gf11.multiply(_a, _b)
    print(f'{_a} x {_b} in {gf11} = {_c}')
    if _c != 5:
        raise ValueError('Multiplication is not working')

    _c = gf11.inverse(_a)
    print(f'{_a} ** -1 in {gf11} = {_c}')
    if _c != 4:
        raise ValueError('Inversion is not working')

    _c = gf11.divide(_a, _b)
    print(f'{_a} / {_b} in {gf11} = {_c}')
    if _c != 4:
        raise ValueError('Division is not working')

    try:
        GaloisField(12)
    except ValueError as msg:
        print(msg)

    gf12 = GaloisField(12, force=True)
    print(gf12)
    try:
        gf12.inverse(3)
    except ValueError as msg:
        print(msg)
