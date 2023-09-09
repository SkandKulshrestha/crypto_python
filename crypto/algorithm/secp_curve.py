# import external library
import numpy as np

# from import external library
from abc import ABC
from typing import Any, Tuple, Union

# from import external library
from ecc_curve import ECCCurve, Point
from secp_curves import secp_curves


class SecpCurve(ECCCurve):
    def __init__(self, curve_name: str):
        super(SecpCurve, self).__init__(curve_name)
        self.p = None  # a prime p which represents prime finite fields
        self.n = None  # a prime n which is the order of G
        self.a = None
        self.b = None
        self.g_x = None
        self.g_y = None
        self.h = None  # an integer h which is the cofactor
        self.S = None

    def _set_domain_parameters(self):
        if self.curve_name in secp_curves:
            self.p, self.n, self.a, self.b, self.g_x, self.g_y, self.h, self.S = secp_curves[self.curve_name]
        else:
            raise ValueError(f'"{self.curve_name}" is not supported')

        # set generating point
        self.G = Point(self.g_x, self.g_y)

    def _point_addition(self, p_x: int, p_y: int) -> Tuple[int, int]:
        pass

    def _point_doubling(self, p_x: int, p_y: int) -> Tuple[int, int]:
        pass

    def _point_multiplication(self, d: int, p_x: int, p_y: int) -> Tuple[int, int]:
        pass


if __name__ == '__main__':
    curve = SecpCurve(curve_name='secp256r1')
    print(curve.get_generating_point())
