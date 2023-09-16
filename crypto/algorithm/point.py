# from import external library
from typing import Union

# from import internal library
from utility import Utility
from warning_crypto import InvalidComparison


class Point:
    def __init__(self, x: Union[str, int], y: Union[str, int]):
        self.x = Utility.convert_to_int(x)
        self.y = Utility.convert_to_int(y)

    def __repr__(self):
        return f'x : 0x{self.get_x()}\n' \
               f'y : 0x{self.get_y()}\n'

    def __eq__(self, other):
        if isinstance(other, Point):
            return self.x == other.x and self.y == other.y
        raise InvalidComparison(self, other)

    def __ne__(self, other):
        return not (self == other)

    def get_x(self) -> str:
        return Utility.convert_int_to_hex_string(self.x)

    def set_x(self, x: str):
        self.x = int(x, 16)

    def get_y(self) -> str:
        return Utility.convert_int_to_hex_string(self.y)

    def set_y(self, y: str):
        self.y = int(y, 16)


if __name__ == '__main__':
    p1 = Point(5, 4)
    print(p1)

    p2 = Point('5', 4)
    print(p2)

    p3 = Point(5, '4')
    print(p3)

    p4 = Point('4', '5')
    print(p4)

    print(f'{p1 == p2 = }')
    print(f'{p1 == p3 = }')
    print(f'{p2 == p3 = }')
    print(f'{p1 == p4 = }')

    try:
        print(p1 == '4')
    except InvalidComparison as e:
        print(e)
