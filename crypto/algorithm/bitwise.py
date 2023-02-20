import numpy as np


class Bitwise:
    def __init__(self):
        pass

    @staticmethod
    def xor2(destination: np.ndarray, source: np.ndarray):
        if len(destination) != len(source):
            raise ValueError('Cannot perform xor between array with different shape'
                             f' ({len(destination)}) and ({len(source)})')

        for i in range(len(destination)):
            destination[i] = destination[i] ^ source[i]
