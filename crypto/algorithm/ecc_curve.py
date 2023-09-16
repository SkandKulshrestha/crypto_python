# from import external library
from abc import ABC
from typing import Any, Tuple, Union

# from import external library
from utility import Utility


class Point:
    def __init__(self, x: Union[str, int], y: Union[str, int]):
        if isinstance(x, str):
            self.set_x(x)
        elif isinstance(x, int):
            self.x = x
        else:
            raise NotImplementedError('Only "str" or "int" is supported for "x"')

        if isinstance(y, str):
            self.set_y(y)
        elif isinstance(y, int):
            self.y = y
        else:
            raise NotImplementedError('Only "str" or "int" is supported for "y"')

    def __repr__(self):
        return f'x : 0x{self.get_x()}\n' \
               f'y : 0x{self.get_y()}\n'

    def __eq__(self, other):
        if isinstance(other, Point):
            return self.x == other.x and self.y == other.y
        else:
            raise SyntaxError('Only "Point" object can be compared')

    def __ne__(self, other):
        return not (self == other)

    def get_x(self) -> str:
        return Utility.convert_to_hex_string(self.x)

    def set_x(self, x: str):
        self.x = int(x, 16)

    def get_y(self) -> str:
        return Utility.convert_to_hex_string(self.y)

    def set_y(self, y: str):
        self.y = int(y, 16)


class ECCCurve(ABC):
    def __init__(self, curve_name: str):
        self.curve_name = curve_name
        self.G = None  # a base point

        # set domain parameters of the curve
        self._initialize_domain_parameters()

    def _initialize_domain_parameters(self):
        raise NotImplementedError('Provide the definition of initialize domain parameters method')

    def _point_negation(self, p_x: int, p_y: int) -> Tuple[int, int]:
        raise NotImplementedError('Provide the definition of point negation method')

    def _point_addition(self, p_x: int, p_y: int, q_x: int, q_y: int) -> Tuple[int, int]:
        raise NotImplementedError('Provide the definition of point addition method')

    def _point_doubling(self, p_x: int, p_y: int) -> Tuple[int, int]:
        raise NotImplementedError('Provide the definition of point doubling method')

    def _point_multiplication(self, d: int, p_x: int, p_y: int) -> Tuple[int, int]:
        raise NotImplementedError('Provide the definition of point multiplication method')

    def _point_subtraction(self, p_x: int, p_y: int, q_x: int, q_y: int) -> Tuple[int, int]:
        raise NotImplementedError('Provide the definition of point subtraction method')

    def get_generating_point(self) -> Point:
        return self.G

    def point_negation(self, point: Point, output_point: Point = None) -> Point:
        _px, _py = self._point_negation(point.x, point.y)

        if output_point is None:
            output_point = Point(_px, _py)
        else:
            output_point.x = _px
            output_point.y = _py

        return output_point

    def point_addition(self, point1: Point, point2: Point, output_point: Point = None) -> Point:
        _px, _py = self._point_addition(point1.x, point1.y, point2.x, point2.y)

        if output_point is None:
            output_point = Point(_px, _py)
        else:
            output_point.x = _px
            output_point.y = _py

        return output_point

    def point_doubling(self, point: Point, output_point: Point = None) -> Point:
        _px, _py = self._point_doubling(point.x, point.y)

        if output_point is None:
            output_point = Point(_px, _py)
        else:
            output_point.x = _px
            output_point.y = _py

        return output_point

    def point_multiplication(self, scalar: str, point: Point, output_point: Point = None):
        _px, _py = self._point_multiplication(int(scalar, 16), point.x, point.y)

        if output_point is None:
            output_point = Point(_px, _py)
        else:
            output_point.x = _px
            output_point.y = _py

        return output_point

    def point_subtraction(self, point1: Point, point2: Point, output_point: Point = None) -> Point:
        _px, _py = self._point_subtraction(point1.x, point1.y, point2.x, point2.y)

        if output_point is None:
            output_point = Point(_px, _py)
        else:
            output_point.x = _px
            output_point.y = _py

        return output_point
