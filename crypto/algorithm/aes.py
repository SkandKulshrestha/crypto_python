import numpy as np

from enum import IntEnum
from typing import Optional, Union
from rijndael import Rijndael, RijndaelBlockSize


class AESKeySize(IntEnum):
    AES_128_BIT_KEY = 16,
    AES_192_BIT_KEY = 24,
    AES_256_BIT_KEY = 32


class AES(Rijndael):
    KEY_SHIFT = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)

    def __init__(self, key: Optional[Union[str, np.ndarray]] = None):
        super(AES, self).__init__(key=key, block_size=RijndaelBlockSize.RIJNDAEL_128_BIT_BLOCK)

    def _validate_block_size(self):
        if self._block_size != 16:
            raise ValueError(f'{self._block_size} is not a valid block size')

    def _validate_key_size(self):
        try:
            AESKeySize(len(self._key))
        except ValueError:
            raise ValueError(f'{len(self._key)} is not a valid key size')


if __name__ == '__main__':
    # refer: https://www.simplilearn.com/tutorials/cryptography-tutorial/aes-encryption#:~:text=
    # The%20AES%20Encryption%20algorithm%20(also,together%20to%20form%20the%20ciphertext.
    _key = '5468617473206D79204B756E67204675'
    _input_data = '54776F204F6E65204E696E652054776F'
    print('Scenario 1')
    print(f'Key {_key}')
    print(f'Plaintext {_input_data}')
    aes = AES()
    aes.set_key(_key)
    _output_data = aes.encrypt(_input_data)
    print(f'Ciphertext {_output_data}')
    if _output_data != '29C3505F571420F6402299B31A02D73A':
        raise RuntimeError('AES encryption fails')

    _output_data = aes.decrypt(_output_data)
    print(f'Plaintext {_output_data}')
    if _output_data != _input_data:
        raise RuntimeError('AES decryption fails')
