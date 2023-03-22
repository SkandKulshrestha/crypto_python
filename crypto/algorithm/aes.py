import numpy as np

from enum import IntEnum
from typing import Optional, Union, Tuple
from utility import Utility
from bitwise import Bitwise
from rijndael import Rijndael


class AesKeySize(IntEnum):
    AES_128_BIT_KEY = 16,
    AES_192_BIT_KEY = 24,
    AES_256_BIT_KEY = 32


class Aes(Rijndael):
    BLOCK_SIZE = 16
    KEY_SHIFT = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)
    S_BOXES = (
        # S1
        (
            (0x0E, 0x04, 0x0D, 0x01, 0x02, 0x0F, 0x0B, 0x08, 0x03, 0x0A, 0x06, 0x0C, 0x05, 0x09, 0x00, 0x07),
            (0x00, 0x0F, 0x07, 0x04, 0x0E, 0x02, 0x0D, 0x01, 0x0A, 0x06, 0x0C, 0x0B, 0x09, 0x05, 0x03, 0x08),
            (0x04, 0x01, 0x0E, 0x08, 0x0D, 0x06, 0x02, 0x0B, 0x0F, 0x0C, 0x09, 0x07, 0x03, 0x0A, 0x05, 0x00),
            (0x0F, 0x0C, 0x08, 0x02, 0x04, 0x09, 0x01, 0x07, 0x05, 0x0B, 0x03, 0x0E, 0x0A, 0x00, 0x06, 0x0D),
        ),

        # S2
        (
            (0x0F, 0x01, 0x08, 0x0E, 0x06, 0x0B, 0x03, 0x04, 0x09, 0x07, 0x02, 0x0D, 0x0C, 0x00, 0x05, 0x0A),
            (0x03, 0x0D, 0x04, 0x07, 0x0F, 0x02, 0x08, 0x0E, 0x0C, 0x00, 0x01, 0x0A, 0x06, 0x09, 0x0B, 0x05),
            (0x00, 0x0E, 0x07, 0x0B, 0x0A, 0x04, 0x0D, 0x01, 0x05, 0x08, 0x0C, 0x06, 0x09, 0x03, 0x02, 0x0F),
            (0x0D, 0x08, 0x0A, 0x01, 0x03, 0x0F, 0x04, 0x02, 0x0B, 0x06, 0x07, 0x0C, 0x00, 0x05, 0x0E, 0x09),
        ),

        # S3
        (
            (0x0A, 0x00, 0x09, 0x0E, 0x06, 0x03, 0x0F, 0x05, 0x01, 0x0D, 0x0C, 0x07, 0x0B, 0x04, 0x02, 0x08),
            (0x0D, 0x07, 0x00, 0x09, 0x03, 0x04, 0x06, 0x0A, 0x02, 0x08, 0x05, 0x0E, 0x0C, 0x0B, 0x0F, 0x01),
            (0x0D, 0x06, 0x04, 0x09, 0x08, 0x0F, 0x03, 0x00, 0x0B, 0x01, 0x02, 0x0C, 0x05, 0x0A, 0x0E, 0x07),
            (0x01, 0x0A, 0x0D, 0x00, 0x06, 0x09, 0x08, 0x07, 0x04, 0x0F, 0x0E, 0x03, 0x0B, 0x05, 0x02, 0x0C),
        ),

        # S4
        (
            (0x07, 0x0D, 0x0E, 0x03, 0x00, 0x06, 0x09, 0x0A, 0x01, 0x02, 0x08, 0x05, 0x0B, 0x0C, 0x04, 0x0F),
            (0x0D, 0x08, 0x0B, 0x05, 0x06, 0x0F, 0x00, 0x03, 0x04, 0x07, 0x02, 0x0C, 0x01, 0x0A, 0x0E, 0x09),
            (0x0A, 0x06, 0x09, 0x00, 0x0C, 0x0B, 0x07, 0x0D, 0x0F, 0x01, 0x03, 0x0E, 0x05, 0x02, 0x08, 0x04),
            (0x03, 0x0F, 0x00, 0x06, 0x0A, 0x01, 0x0D, 0x08, 0x09, 0x04, 0x05, 0x0B, 0x0C, 0x07, 0x02, 0x0E),
        ),

        # S5
        (
            (0x02, 0x0C, 0x04, 0x01, 0x07, 0x0A, 0x0B, 0x06, 0x08, 0x05, 0x03, 0x0F, 0x0D, 0x00, 0x0E, 0x09),
            (0x0E, 0x0B, 0x02, 0x0C, 0x04, 0x07, 0x0D, 0x01, 0x05, 0x00, 0x0F, 0x0A, 0x03, 0x09, 0x08, 0x06),
            (0x04, 0x02, 0x01, 0x0B, 0x0A, 0x0D, 0x07, 0x08, 0x0F, 0x09, 0x0C, 0x05, 0x06, 0x03, 0x00, 0x0E),
            (0x0B, 0x08, 0x0C, 0x07, 0x01, 0x0E, 0x02, 0x0D, 0x06, 0x0F, 0x00, 0x09, 0x0A, 0x04, 0x05, 0x03),
        ),

        # S6
        (
            (0x0C, 0x01, 0x0A, 0x0F, 0x09, 0x02, 0x06, 0x08, 0x00, 0x0D, 0x03, 0x04, 0x0E, 0x07, 0x05, 0x0B),
            (0x0A, 0x0F, 0x04, 0x02, 0x07, 0x0C, 0x09, 0x05, 0x06, 0x01, 0x0D, 0x0E, 0x00, 0x0B, 0x03, 0x08),
            (0x09, 0x0E, 0x0F, 0x05, 0x02, 0x08, 0x0C, 0x03, 0x07, 0x00, 0x04, 0x0A, 0x01, 0x0D, 0x0B, 0x06),
            (0x04, 0x03, 0x02, 0x0C, 0x09, 0x05, 0x0F, 0x0A, 0x0B, 0x0E, 0x01, 0x07, 0x06, 0x00, 0x08, 0x0D),
        ),

        # S7
        (
            (0x04, 0x0B, 0x02, 0x0E, 0x0F, 0x00, 0x08, 0x0D, 0x03, 0x0C, 0x09, 0x07, 0x05, 0x0A, 0x06, 0x01),
            (0x0D, 0x00, 0x0B, 0x07, 0x04, 0x09, 0x01, 0x0A, 0x0E, 0x03, 0x05, 0x0C, 0x02, 0x0F, 0x08, 0x06),
            (0x01, 0x04, 0x0B, 0x0D, 0x0C, 0x03, 0x07, 0x0E, 0x0A, 0x0F, 0x06, 0x08, 0x00, 0x05, 0x09, 0x02),
            (0x06, 0x0B, 0x0D, 0x08, 0x01, 0x04, 0x0A, 0x07, 0x09, 0x05, 0x00, 0x0F, 0x0E, 0x02, 0x03, 0x0C),
        ),

        # S8
        (
            (0x0D, 0x02, 0x08, 0x04, 0x06, 0x0F, 0x0B, 0x01, 0x0A, 0x09, 0x03, 0x0E, 0x05, 0x00, 0x0C, 0x07),
            (0x01, 0x0F, 0x0D, 0x08, 0x0A, 0x03, 0x07, 0x04, 0x0C, 0x05, 0x06, 0x0B, 0x00, 0x0E, 0x09, 0x02),
            (0x07, 0x0B, 0x04, 0x01, 0x09, 0x0C, 0x0E, 0x02, 0x00, 0x06, 0x0A, 0x0D, 0x0F, 0x03, 0x05, 0x08),
            (0x02, 0x01, 0x0E, 0x07, 0x04, 0x0A, 0x08, 0x0D, 0x0F, 0x0C, 0x09, 0x00, 0x03, 0x05, 0x06, 0x0B),
        )
    )

    def __init__(self, key: Optional[Union[str, np.ndarray]] = None):
        super(Aes, self).__init__(key=key, no_of_rounds=16)

        self._working_buffer = np.zeros((self.BLOCK_SIZE,), dtype=np.uint8)

    def _validate_key(self):
        try:
            AesKeySize(len(self._key))
        except ValueError:
            raise ValueError(f'{len(self._key)} is not a valid key size')

    def key_schedule(self):
        self._round_key = np.zeros((self.no_of_rounds, self.BLOCK_SIZE), dtype=np.uint8)

        for i in range(self.no_of_rounds):
            pass

    def round_function(self, input_data: np.ndarray, key: np.ndarray):

        return input_data

    def set_key(self, key: Union[str, np.ndarray]):
        super(Aes, self).set_key(key)

    def _encrypt_one_block(self, data: np.ndarray):
        return data

    def _decrypt_one_block(self, data: np.ndarray):
        return data

    def encrypt(self, input_data: Union[str, np.ndarray], output_data: np.ndarray = None) -> Union[str, np.ndarray]:
        output_data = Utility.copy_to_numpy(input_data, out_data=output_data, error_msg='Invalid plaintext')

        if len(output_data) % self.BLOCK_SIZE:
            raise ValueError(f'Input data is not multiple of block length ({self.BLOCK_SIZE} bytes)')

        no_of_blocks = len(output_data) // self.BLOCK_SIZE

        for i in range(no_of_blocks):
            _start = i * no_of_blocks
            _end = _start + self.BLOCK_SIZE
            output_data[_start: _end] = self._encrypt_one_block(output_data[_start: _end])

        if isinstance(input_data, str):
            output_data = Utility.convert_to_str(output_data)

        return output_data

    def decrypt(self, input_data: Union[str, np.ndarray], output_data: np.ndarray = None) -> Union[str, np.ndarray]:
        output_data = Utility.copy_to_numpy(input_data, out_data=output_data, error_msg='Invalid ciphertext')

        if len(output_data) % self.BLOCK_SIZE:
            raise ValueError(f'Input data is not multiple of block length ({self.BLOCK_SIZE} bytes)')

        no_of_blocks = len(output_data) // self.BLOCK_SIZE

        for i in range(no_of_blocks):
            _start = i * no_of_blocks
            _end = _start + self.BLOCK_SIZE
            output_data[_start: _end] = self._decrypt_one_block(output_data[_start: _end])

        if isinstance(input_data, str):
            output_data = Utility.convert_to_str(output_data)

        return output_data


if __name__ == '__main__':
    # refer: https://www.simplilearn.com/tutorials/cryptography-tutorial/aes-encryption#:~:text=
    # The%20AES%20Encryption%20algorithm%20(also,together%20to%20form%20the%20ciphertext.
    _key = '5468617473206D79204B756E67204675'
    _input_data = '54776F204F6E652043696E252054776F'
    print('Scenario 1')
    print(f'Key {_key}')
    print(f'Plaintext {_input_data}')
    aes = Aes()
    aes.set_key(_key)
    _output_data = aes.encrypt(_input_data)
    print(f'Ciphertext {_output_data}')
    if _output_data != '29C3505F571420F6402299B31A02D73A':
        raise RuntimeError('Aes encryption fails')

    _output_data = aes.decrypt(_output_data)
    print(f'Plaintext {_output_data}')
    if _output_data != _input_data:
        raise RuntimeError('Aes decryption fails')
