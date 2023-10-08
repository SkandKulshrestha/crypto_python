# import external library
import numpy as np

# from import external library
from enum import IntEnum


class PaddingScheme(IntEnum):
    M1 = 1
    M2 = 2
    M3 = 3
    PKCS = 4


class Padding:
    def __init__(self, pad_scheme: PaddingScheme, block_size: int):
        # store pad scheme and block size
        self.pad_scheme = pad_scheme
        self.block_size = block_size

        # set apply and remove method
        self.apply_padding = eval(f'self.apply_{pad_scheme.name.lower()}')
        self.remove_padding = eval(f'self.remove_{pad_scheme.name.lower()}')

    def apply_m1(self, data: np.ndarray) -> np.ndarray:
        # calculate remaining length
        remaining_length = len(data) % self.block_size

        if remaining_length:
            # calculate pad length
            pad_length = self.block_size - remaining_length

            # append padding
            _data = np.zeros((len(data) + pad_length), dtype=data.dtype)
            _data[:len(data)] = data[:]
        else:
            _data = data

        return _data

    def remove_m1(self, data: np.ndarray) -> np.ndarray:
        if self.block_size:
            # handle unused warning
            pass

        # do nothing, since M0 padding cannot be removed as last zero bytes may be data

        return data

    def apply_m2(self, data: np.ndarray) -> np.ndarray:
        # calculate remaining length
        remaining_length = len(data) % self.block_size

        # calculate pad length
        if remaining_length:
            pad_length = self.block_size - remaining_length
        else:
            pad_length = self.block_size

        # append padding
        _data = np.zeros((len(data) + pad_length), dtype=data.dtype)
        _data[:len(data)] = data[:]
        _data[len(data)] = 0x80

        return _data

    def remove_m2(self, data: np.ndarray) -> np.ndarray:
        if self.block_size:
            # handle unused warning
            pass

        # find first pad byte, i.e., 0x80
        i = len(data) - 1
        while data[i] == 0x00:
            i -= 1

        # remove padding
        _data = np.zeros((i,), dtype=data.dtype)
        _data[:] = data[:i]

        return _data

    def apply_pkcs(self, data: np.ndarray) -> np.ndarray:
        # calculate remaining length
        remaining_length = len(data) % self.block_size

        # calculate pad length
        if remaining_length:
            pad_length = self.block_size - remaining_length
        else:
            pad_length = self.block_size

        # append padding
        _data = np.zeros((len(data) + pad_length), dtype=data.dtype)
        _data[:len(data)] = data[:]
        for i in range(len(data), len(_data)):
            _data[i] = pad_length

        return _data

    def remove_pkcs(self, data: np.ndarray) -> np.ndarray:
        if self.block_size:
            # handle unused warning
            pass

        # read last byte
        pad_length = data[-1]

        # remove padding
        _data = np.zeros((len(data) - pad_length,), dtype=data.dtype)
        _data[:] = data[:len(_data)]

        return _data


if __name__ == '__main__':
    data1 = np.array([0x01, 0x02, 0x03, 0x04])
    data2 = np.array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])

    print(f'{data1 = }')
    print(f'{data2 = }')

    print('-' * 80)
    print('Scenario 1: M1 on incomplete block')
    pad = Padding(PaddingScheme.M1, 8)
    _out = pad.apply_padding(data1)
    print(f'Add M1 pad to data1: {_out}')
    _out = pad.remove_padding(_out)
    print(f'Remove M1 pad from data1: {_out}')

    print('-' * 80)
    print('Scenario 2: M1 on complete block')
    pad = Padding(PaddingScheme.M1, 8)
    _out = pad.apply_padding(data2)
    print(f'Add M1 pad to data2: {_out}')
    _out = pad.remove_padding(_out)
    print(f'Remove M1 pad from data1: {_out}')

    print('-' * 80)
    print('Scenario 3: M2 on incomplete block')
    pad = Padding(PaddingScheme.M2, 8)
    _out = pad.apply_padding(data1)
    print(f'Add M2 pad to data1: {_out}')
    _out = pad.remove_padding(_out)
    print(f'Remove M2 pad from data1: {_out}')

    print('-' * 80)
    print('Scenario 4: M2 on complete block')
    pad = Padding(PaddingScheme.M2, 8)
    _out = pad.apply_padding(data2)
    print(f'Add M2 pad to data2: {_out}')
    _out = pad.remove_padding(_out)
    print(f'Remove M2 pad from data1: {_out}')

    print('-' * 80)
    print('Scenario 5: PKCS on incomplete block')
    pad = Padding(PaddingScheme.PKCS, 8)
    _out = pad.apply_padding(data1)
    print(f'Add PKCS pad to data1: {_out}')
    _out = pad.remove_padding(_out)
    print(f'Remove PKCS pad from data1: {_out}')

    print('-' * 80)
    print('Scenario 6: PKCS on complete block')
    pad = Padding(PaddingScheme.PKCS, 8)
    _out = pad.apply_padding(data2)
    print(f'Add PKCS pad to data2: {_out}')
    _out = pad.remove_padding(_out)
    print(f'Remove PKCS pad from data1: {_out}')
