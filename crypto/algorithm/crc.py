# from import external library
from typing import Tuple


class CRCAlgo:
    ALGO = {
        # poly: int, init: int, ref_in: bool, ref_out: bool, xor_out: int
        'CRC16': (0x1021, 0x0000, False, False, 0x0000),
        'CRC16-INIT': (0x1021, 0x0000, True, False, 0x0000),
        'CRC32': (0x10211234, 0x00000000, False, False, 0x00000000)
    }

    def __init__(self, crc: str):
        if crc not in self.ALGO:
            raise ValueError(f'Parameters for "{crc}" are not defined')
        self.crc = crc

    def fetch_parameters(self) -> Tuple[int, int, bool, bool, int]:
        return self.ALGO[self.crc]

    @staticmethod
    def support_algorithm():
        print('=' * 80)
        print('Algorithm               Poly       Init       Ref In       Ref Out       XOR Out')
        print('-' * 80)
        for k, v in CRCAlgo.ALGO.items():
            poly, init, ref_in, ref_out, xor_out = v
            print(f'{k} 0x{poly:04} {v[1]} {v[2]} {v[3]} {v[4]}')
        print('=' * 80)


class CRC:
    def __init__(self, poly: int, init: int, ref_in: bool, ref_out: bool, xor_out: int, crc: str = ''):
        self.poly = poly
        self.init = init
        self.ref_in = ref_in
        self.ref_out = ref_out
        self.xor_out = xor_out
        self.crc = crc

    def __repr__(self):
        return f'{self.crc if self.crc else "CRC"}\n' \
               f'    Polynomial : 0x{self.poly:04X}\n' \
               f'    Init : 0x{self.init:04X}\n' \
               f'    Reflection In : {self.ref_in}\n' \
               f'    Reflection Out : {self.ref_out}\n' \
               f'    XOR Out : 0x{self.xor_out:04X}\n'

    @classmethod
    def with_(cls, crc: str):
        params = CRCAlgo(crc).fetch_parameters()
        obj = CRC(*params)
        obj.crc = crc
        return obj

    def compute(self, data, final=True):
        # process data
        pass


if __name__ == '__main__':
    CRCAlgo.support_algorithm()

    crc_obj = CRC.with_('CRC16')
    # print(crc_obj)

    crc_obj.compute('0000')
