# import external library
import numpy as np
import warnings

# from import external library
from enum import IntEnum

# from import internal library
from des import DES
from warning_crypto import DeprecatedWarning, DisallowedWarning, KeyParityWarning


class TDESKeySize(IntEnum):
    TDES_128_BIT_KEY = 16
    TDES_192_BIT_KEY = 24


class TDES(DES):
    def __init__(self):
        super(TDES, self).__init__()

        self._operation = 0

    def _validate_key_size(self):
        try:
            TDESKeySize(len(self._key))

            warnings.warn('TDES will be deprecated for all applications through 2023', DeprecatedWarning)
            warnings.warn('TDES will be disallowed after December 31, 2023', DisallowedWarning)

            # check for odd parity
            for k in self._key:
                if bin(k).count('1') % 2 == 0:
                    warnings.warn(f'TDES key parity bit for {k:02X} is not valid', KeyParityWarning)
                    break
        except ValueError:
            raise ValueError(f'{len(self._key)} is not a valid key size')

    def _key_schedule(self):
        self._key_size = len(self._key)
        self._round_key = np.zeros((3, self._no_of_rounds, self._block_size), dtype=np.uint8)

        for operation in range(3):
            if operation == 2 and self._key_size == TDESKeySize.TDES_128_BIT_KEY:
                self._round_key[2, :, :] = self._round_key[0, :, :]
                continue

            left, right = self._permutation_choice1(self._key[operation * 8:(operation + 1) * 8])
            for _round in range(self._no_of_rounds):
                right = self._left_circular_rotate(right, self._KEY_SHIFT[_round])
                left = self._left_circular_rotate(left, self._KEY_SHIFT[_round])
                self._permutation_choice2(left, right, self._round_key[operation][_round])

    def get_round_key(self, round_no: int) -> np.ndarray:
        if self._round_key is None:
            raise ValueError('Key is not set')

        return self._round_key[self._operation, round_no]

    def set_operation(self, operation):
        self._operation = operation

    def _encrypt(self, buffer: np.ndarray):
        self._initial_permutation(buffer)

        self.set_operation(0)
        super(DES, self)._encrypt(buffer)

        self.set_operation(1)
        super(DES, self)._decrypt(buffer)

        self.set_operation(2)
        super(DES, self)._encrypt(buffer)

        self._inverse_initial_permutation(buffer)

        return buffer

    def _decrypt(self, buffer: np.ndarray):
        self._initial_permutation(buffer)

        self.set_operation(2)
        super(DES, self)._decrypt(buffer)

        self.set_operation(1)
        super(DES, self)._encrypt(buffer)

        self.set_operation(0)
        super(DES, self)._decrypt(buffer)

        self._inverse_initial_permutation(buffer)

        return buffer


if __name__ == '__main__':
    _key = '133457799BBCDFF1133457799BBCDFF1'
    _input_data = '0123456789ABCDEF'
    print('Scenario 1')
    print(f'Key {_key}')
    print(f'Plaintext {_input_data}')
    tdes = TDES()
    warnings.filterwarnings("ignore", category=DeprecatedWarning)
    warnings.filterwarnings("ignore", category=DisallowedWarning)
    tdes.set_key(_key)
    warnings.resetwarnings()
    _output_data = tdes.encrypt(_input_data)
    print(f'Ciphertext {_output_data}')
    if _output_data != '85E813540F0AB405':
        raise RuntimeError('TDES encryption fails')

    _output_data = tdes.decrypt(_output_data)
    print(f'Plaintext {_output_data}')
    if _output_data != _input_data:
        raise RuntimeError('TDES decryption fails')

    _key = '133457799BBCDFF11557799BBCCDDFF1'
    _input_data = '0123456789ABCDEF'
    print('Scenario 2')
    print(f'Key {_key}')
    print(f'Plaintext {_input_data}')
    tdes = TDES()
    warnings.filterwarnings("ignore", category=DeprecatedWarning)
    warnings.filterwarnings("ignore", category=DisallowedWarning)
    tdes.set_key(_key)
    warnings.resetwarnings()
    _output_data = tdes.encrypt(_input_data)
    print(f'Ciphertext {_output_data}')
    if _output_data != '0467366CF3B1D285':
        raise RuntimeError('TDES encryption fails')

    _output_data = tdes.decrypt(_output_data)
    print(f'Plaintext {_output_data}')
    if _output_data != _input_data:
        raise RuntimeError('TDES decryption fails')

    _key = '133457799BBCDFF11557799BBCCDDFF1133457799BBCDFF1'
    _input_data = '0123456789ABCDEF'
    print('Scenario 3')
    print(f'Key {_key}')
    print(f'Plaintext {_input_data}')
    tdes = TDES()
    warnings.filterwarnings("ignore", category=DeprecatedWarning)
    warnings.filterwarnings("ignore", category=DisallowedWarning)
    tdes.set_key(_key)
    warnings.resetwarnings()
    _output_data = tdes.encrypt(_input_data)
    print(f'Ciphertext {_output_data}')
    if _output_data != '0467366CF3B1D285':
        raise RuntimeError('TDES encryption fails')

    _output_data = tdes.decrypt(_output_data)
    print(f'Plaintext {_output_data}')
    if _output_data != _input_data:
        raise RuntimeError('TDES decryption fails')

    _key = '133457799BBCDFF11557799BBCCDDFF1133457799BBCCDDF'
    _input_data = '0123456789ABCDEF'
    print('Scenario 4')
    print(f'Key {_key}')
    print(f'Plaintext {_input_data}')
    tdes = TDES()
    warnings.filterwarnings("ignore", category=DeprecatedWarning)
    warnings.filterwarnings("ignore", category=DisallowedWarning)
    tdes.set_key(_key)
    warnings.resetwarnings()
    _output_data = tdes.encrypt(_input_data)
    print(f'Ciphertext {_output_data}')
    if _output_data != 'A1DD8F6BD298CC49':
        raise RuntimeError('TDES encryption fails')

    _output_data = tdes.decrypt(_output_data)
    print(f'Plaintext {_output_data}')
    if _output_data != _input_data:
        raise RuntimeError('TDES decryption fails')
