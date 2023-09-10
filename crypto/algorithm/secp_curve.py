# from import external library
from typing import Tuple

# from import external library
from ecc_curve import ECCCurve, Point
from secp_curves import secp_curves
from utility import Utility


class SecpCurve(ECCCurve):
    def __init__(self, curve_name: str):
        super(SecpCurve, self).__init__(curve_name)

    def _set_domain_parameters(self):
        if self.curve_name in secp_curves:
            self.p, self.n, self.a, self.b, self.g_x, self.g_y, self.h, self.S = secp_curves[self.curve_name]
        else:
            raise ValueError(f'"{self.curve_name}" is not supported')

        # set generating point
        self.G = Point(self.g_x, self.g_y)

    def _point_negation(self, p_x: int, p_y: int) -> Tuple[int, int]:
        # P + (-P) = O
        # (x, -y) = -(x, y)
        p_y = Utility.modulus(-p_y, self.p)

        return p_x, p_y

    def _calculate_x_y(self, _lambda: int, p_x: int, p_y: int, q_x: int):
        # r_x = (_lambda ** 2) - p_x - q_x
        r_x = Utility.modulus(_lambda * _lambda, self.p)
        r_x = Utility.modulus(r_x - p_x - q_x, self.p)

        # r_y = _lambda * (p_x - r_x) - p_y
        r_y = Utility.modulus(p_x - r_x, self.p)
        r_y = Utility.modulus(_lambda * r_y, self.p)
        r_y = Utility.modulus(r_y - p_y, self.p)

        return r_x, r_y

    def _point_addition(self, p_x: int, p_y: int, q_x: int, q_y: int) -> Tuple[int, int]:
        if p_x == q_x and p_y == q_y:
            # perform point double
            return self._point_doubling(p_x, p_y)

        # P + Q = R
        # _lambda = (q_y - p_y) / (q_x - p_x)
        _delta_x = Utility.modulus(q_x - p_x, self.p)
        _delta_y = Utility.modulus(q_y - p_y, self.p)
        _delta_x_inv = Utility.inverse(_delta_x, self.p)
        _lambda = Utility.modulus(_delta_y * _delta_x_inv, self.p)

        # r_x = (_lambda ** 2) - p_x - q_x
        # r_y = _lambda * (p_x - r_x) - p_y
        return self._calculate_x_y(_lambda, p_x, p_y, q_x)

    def _point_doubling(self, p_x: int, p_y: int) -> Tuple[int, int]:
        # P + Q = R, Q = p => 2P = R
        # _lambda = (3 * (p_x**2) + a) / (2 * p_y)
        _denominator = Utility.modulus(2 * p_y, self.p)
        _numerator = Utility.modulus(3 * p_x * p_x, self.p)
        _numerator = Utility.modulus(_numerator + self.a, self.p)
        _denominator_inv = Utility.inverse(_denominator, self.p)
        _lambda = Utility.modulus(_numerator * _denominator_inv, self.p)

        # r_x = (_lambda ** 2) - p_x - p_x
        # r_y = _lambda * (p_x - r_x) - p_y
        return self._calculate_x_y(_lambda, p_x, p_y, p_x)

    def _point_multiplication(self, d: int, p_x: int, p_y: int) -> Tuple[int, int]:
        # let bits = bit_representation(s) # the vector of bits (from LSB to MSB) representing s
        bits = bin(d)[2:]
        i = 1

        # let res = P
        res_x, res_y = p_x, p_y

        # traversing from second MSB to LSB
        while i < len(bits):
            # res = res + res # double
            res_x, res_y = self._point_doubling(res_x, res_y)
            if bits[i] == '1':
                # res = res + P  # add
                res_x, res_y = self._point_addition(res_x, res_y, p_x, p_y)
            i += 1

        # return res
        return res_x, res_y


if __name__ == '__main__':
    # https://asecuritysite.com/ecc/ecc_mont
    curve = SecpCurve(curve_name='secp256r1')

    print('G')
    _g = curve.get_generating_point()
    print(_g)

    print('1G = internally nothing')
    _1G_point = curve.point_multiplication(
        scalar='01',
        point=_g
    )
    print(_1G_point)

    print('2G = internally point doubling, i.e., 2 * G')
    _2G_point = curve.point_multiplication(
        scalar='02',
        point=_g
    )
    print(_2G_point)

    print('3G = internally point doubling followed by point addition, 2 * G + G')
    _3G_point = curve.point_multiplication(
        scalar='03',
        point=_g
    )
    print(_3G_point)

    print('4G = internally point doubling, i.e., 2 * (2 * G)')
    _4G_point = curve.point_multiplication(
        scalar='04',
        point=_g
    )
    print(_4G_point)

    print('4G = 3G + G')
    _4G_point_addition = curve.point_addition(
        point1=_3G_point,
        point2=_1G_point
    )
    print(_4G_point_addition)

    if _4G_point != _4G_point_addition:
        raise ValueError('Point multiplication and point addition is not yielding same result')

    print('5G = internally point doubling followed by point addition, i.e., (2 * (2 * G)) + G')
    _5G_point = curve.point_multiplication(
        scalar='05',
        point=_g
    )
    print(_5G_point)

    print('5G = 3G + 2G')
    _5G_point_addition = curve.point_addition(
        point1=_3G_point,
        point2=_2G_point
    )
    print(_5G_point_addition)

    if _5G_point != _5G_point_addition:
        raise ValueError('Point multiplication and point addition is not yielding same result')

    print('nG')
    _nG_point = curve.point_multiplication(
        scalar=Utility.convert_to_hex_string(curve.n),
        point=_g
    )
    print(_nG_point)

    print('(n+1)G')
    _n_plus1_G_point = curve.point_multiplication(
        scalar=Utility.convert_to_hex_string(curve.n + 1),
        point=_g
    )
    print(_n_plus1_G_point)

    print('(n+1)G = nG + 1')
    _n_plus1_G_point_addition = curve.point_addition(
        point1=_nG_point,
        point2=_1G_point
    )
    print(_n_plus1_G_point_addition)
