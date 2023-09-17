# from import external library
from typing import Union

# from import internal library
from utility import Utility


class GaloisField:
    def __init__(self, order: Union[str, int]):
        self.order = Utility.convert_to_int(order)

    def __repr__(self):
        return f"GF({self.order})"

    def __eq__(self, other):
        pass

    def __ne__(self, other):
        pass

    def __add__(self, other):
        pass

    def __mul__(self, other):
        pass

    def __pow__(self, power, modulo=None):
        pass

    def set_order(self, order: str):
        self.order = Utility.convert_hex_string_to_int(order)

    def get_order(self):
        return Utility.convert_int_to_hex_string(self.order)

    def addition(self, a: int, b: int):
        return (a + b) % self.order

    def multiplication(self, a: int, b: int):
        pass


if __name__ == '__main__':
    gf2 = GaloisField(2)
    print(gf2)
