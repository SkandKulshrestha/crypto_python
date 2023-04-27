import numpy as np

from bitwise import Bitwise


class KeccakP:
    B = (25, 50, 100, 200, 400, 800, 1600)

    # b/25
    # W = (1, 2, 4, 8, 16, 32, 64)
    # log2(b/25)
    # L = (0, 1, 2, 3, 4, 5, 6)

    def __init__(self, b: int, nr: int):
        # The width is denoted by b: the fixed
        # length of the strings that are permuted, called the width of the permutation
        # the number of rounds is denoted by nr: the number of
        # iterations of an internal transformation, called a round
        if b not in self.B:
            raise ValueError('In section 3 of NIST FIPS 202, the permutation is '
                             'defined for any b in {25, 50, 100, 200, 400, 800, 1600}')

        self.b = b
        self.nr = nr

        self.w = b / 25
        self.l_ = self.B.index(b)
        self.state = np.zeros((5, 5, self.w), dtype=np.uint8)

    def __setstate__(self, state: np.ndarray):
        pass

    def __getstate__(self):
        return self.state

    def _theta(self):
        Bitwise.xor()
        c = np.bitwise_xor(self.state[:, 0, :], self.state[:, 1, :])
        c = np.bitwise_xor(c, self.state[:, 2, :])
        c = np.bitwise_xor(c, self.state[:, 3, :])
        c = np.bitwise_xor(c, self.state[:, 4, :])

        d = c

    def _rho(self):
        pass

    def _pi(self):
        pass

    def _chi(self):
        pass

    def _iota(self, ir):
        pass

    def _round_function(self):
        for ir in range(self.nr):
            self._theta()
            self._rho()
            self._pi()
            self._chi()
            self._iota(ir)
