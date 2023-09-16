# from import external library
from typing import Tuple

# from import internal library
from ecc_curve import ECCCurve, Point
from secp_curves import secp_curves
from utility import Utility
from warning_crypto import PointAtInfinity


class SecpCurve(ECCCurve):
    def __init__(self, curve_name: str):
        super(SecpCurve, self).__init__(curve_name)

    def _initialize_domain_parameters(self):
        if self.curve_name in secp_curves:
            self.p, self.a, self.b, self.g_x, self.g_y, self.n, self.h, self.S = secp_curves[self.curve_name]
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
        if _delta_x == 0:
            raise PointAtInfinity('Point Addition')

        _delta_x_inv = Utility.inverse(_delta_x, self.p)
        _lambda = Utility.modulus(_delta_y * _delta_x_inv, self.p)

        # r_x = (_lambda ** 2) - p_x - q_x
        # r_y = _lambda * (p_x - r_x) - p_y
        return self._calculate_x_y(_lambda, p_x, p_y, q_x)

    def _point_doubling(self, p_x: int, p_y: int) -> Tuple[int, int]:
        # P + Q = R, Q = P => 2P = R
        # _lambda = (3 * (p_x**2) + a) / (2 * p_y)
        _denominator = Utility.modulus(2 * p_y, self.p)
        _numerator = Utility.modulus(3 * p_x * p_x + self.a, self.p)
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

        try:
            # traversing from second MSB to LSB
            while i < len(bits):
                # res = res + res # double
                res_x, res_y = self._point_doubling(res_x, res_y)
                if bits[i] == '1':
                    # res = res + P  # add
                    res_x, res_y = self._point_addition(res_x, res_y, p_x, p_y)
                i += 1
        except PointAtInfinity:
            raise PointAtInfinity('Point Multiplication')

        # return res
        return res_x, res_y

    def _point_subtraction(self, p_x: int, p_y: int, q_x: int, q_y: int) -> Tuple[int, int]:
        # R = -Q
        r_x, r_y = self._point_negation(q_x, q_y)

        if p_x == r_x:
            raise PointAtInfinity('Point Subtraction')

        # perform P + R
        return self._point_addition(p_x, p_y, r_x, r_y)


if __name__ == '__main__':
    # https://asecuritysite.com/ecc/ecc_mont
    curve = SecpCurve(curve_name='secp256r1')

    print('G')
    _g = curve.get_generating_point()
    print(_g)

    print('Calculating 1G = internally nothing')
    _1G_point = curve.point_multiplication(
        scalar='01',
        point=_g
    )
    print(_1G_point)

    print('Calculating 2G = internally point doubling, i.e., 2 * G')
    _2G_point = curve.point_multiplication(
        scalar='02',
        point=_g
    )
    print(_2G_point)

    print('Calculating 3G = internally point doubling followed by point addition, 2 * G + G')
    _3G_point = curve.point_multiplication(
        scalar='03',
        point=_g
    )
    print(_3G_point)

    print('Calculating 4G = internally point doubling, i.e., 2 * (2 * G)')
    _4G_point = curve.point_multiplication(
        scalar='04',
        point=_g
    )
    print(_4G_point)

    print('Calculating 4G = 3G + G')
    _4G_point_addition = curve.point_addition(
        point1=_3G_point,
        point2=_1G_point
    )
    print(_4G_point_addition)

    if _4G_point != _4G_point_addition:
        raise ValueError('Point multiplication and point addition is not yielding same result')

    print('Calculating 3G = 4G - G')
    _3G_point_subtraction = curve.point_subtraction(
        point1=_4G_point_addition,
        point2=_1G_point
    )
    print(_3G_point_subtraction)

    if _3G_point != _3G_point_subtraction:
        raise ValueError('Point multiplication and point subtraction is not yielding same result')

    print('Calculating 5G = internally point doubling followed by point addition, i.e., (2 * (2 * G)) + G')
    _5G_point = curve.point_multiplication(
        scalar='05',
        point=_g
    )
    print(_5G_point)

    print('Calculating 5G = 3G + 2G')
    _5G_point_addition = curve.point_addition(
        point1=_3G_point,
        point2=_2G_point
    )
    print(_5G_point_addition)

    if _5G_point != _5G_point_addition:
        raise ValueError('Point multiplication and point addition is not yielding same result')

    print(f'n: {curve.n}')
    print(f'n: 0x{Utility.convert_int_to_hex_string(curve.n)}')

    print('Calculating (n-1)G')
    _n_minus1_G_point = curve.point_multiplication(
        scalar=Utility.convert_int_to_hex_string(curve.n - 1),
        point=_g
    )
    print(_n_minus1_G_point)

    try:
        print('Calculating nG = (n-1)G + 1')
        _nG_point_addition = curve.point_addition(
            point1=_n_minus1_G_point,
            point2=_1G_point
        )
        print(_nG_point_addition)
    except PointAtInfinity as e:
        print(e)
        print()

    try:
        print('Calculating nG')
        _nG_point = curve.point_multiplication(
            scalar=Utility.convert_int_to_hex_string(curve.n),
            point=_g
        )
        print(_nG_point)
    except PointAtInfinity as e:
        print(e)
        print()

    print('Calculating (n+1)G')
    _n_plus1_G_point = curve.point_multiplication(
        scalar=Utility.convert_int_to_hex_string(curve.n + 1),
        point=_g
    )
    print(_n_plus1_G_point)

    try:
        print('Calculating nG = (n+1)G - G')
        _nG_point_subtraction = curve.point_subtraction(
            point1=_n_plus1_G_point,
            point2=_1G_point
        )
        print(_nG_point_subtraction)
    except PointAtInfinity as e:
        print(e)
        print()

    _d = Utility.remove_space(
        '7C 2B A2 9B F1 48 9C C5 EF 70 91 C0 6D E4 8C C1 A6 63 02 88 D5 4E 94 A4 D0 F9 CC CF A3 90 2C 32'
    )

    print('Calculating dG')
    _dG_point = curve.point_multiplication(
        scalar=_d,
        point=_g
    )
    print(f'd : 0x{_d}')
    print(_dG_point)
    _x = _dG_point.get_x()
    _y = _dG_point.get_y()
    if _x != Utility.remove_space(
            'DB C9 12 12 CB 30 E5 C8 84 02 5A C8 ED 8F B6 1C C2 55 8E CA 72 E1 38 70 01 AF 5B A1 31 C9 51 EE'
    ):
        raise ValueError
    if _y != Utility.remove_space(
            '22 C0 F5 0E E3 39 FB A7 00 67 94 8A C5 1D 0E 48 0B 40 CD 6E EE EB 9D 05 BB F3 E9 F6 78 39 D8 EB'
    ):
        raise ValueError
