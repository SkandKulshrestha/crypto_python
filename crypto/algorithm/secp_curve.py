# import external library
import numpy as np

# from import external library
from abc import ABC
from typing import Any, Tuple, Union

# from import external library
from utility import Utility
from ecc_curve import ECCCurve, Point

secp_curve = {}


class SecpCurve(ECCCurve):
    def __init__(self, curve_name: str):
        super(SecpCurve, self).__init__(curve_name)
        self.p = None
        self.n = None
        self.a = None
        self.b = None
        self.g = None
        self.g_x = None
        self.g_y = None
        self.h = None

    def _set_domain_parameters(self):
        self.p, self.n, self.a, self.b, self.g_x, self.g_y, self.h = secp_curve[self.curve_name]
        self.g = Point(self.g_x, self.g_y)

    def _point_addition(self, p_x: int, p_y: int) -> Tuple[int, int]:
        pass

    def _point_doubling(self, p_x: int, p_y: int) -> Tuple[int, int]:
        pass

    def _point_multiplication(self, d: int, p_x: int, p_y: int) -> Tuple[int, int]:
        pass
