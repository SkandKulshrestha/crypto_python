# from import external library
from abc import ABC
from typing import Tuple

# from import internal library
from point import Point
from utility import Utility


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
        _px, _py = self._point_multiplication(Utility.convert_hex_string_to_int(scalar), point.x, point.y)

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
