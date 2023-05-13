import numpy as np

from enum import IntEnum
from typing import Optional, Union, Any
from utility import Utility
from padding import Padding


class SymmetricModesOfOperation(IntEnum):
    # Electronic codebook
    ECB = 0,
    # Cipher block chaining
    CBC = 1,
    # Propagating CBC
    PCBC = 2,
    # Output feedback
    OFB = 3,
    # Cipher feedback
    CFB = 4,
    # Counter
    CTR = 5


class Symmetric:
    def __init__(self, key: Optional[Union[str, np.ndarray]] = None,
                 iv: Optional[Union[str, np.ndarray]] = None,
                 no_of_rounds: int = 0, block_size: int = 0):
        # store key and iv as passed
        self.key = key
        self.iv = iv

        # store key size, block size, and number of rounds
        self._key_size = 0
        self._block_size = block_size
        self._no_of_rounds = no_of_rounds

        # store key and iv as numpy array
        self._key = None
        self._iv = None

        # store round key as numpy array
        self._round_key = None

        # set key if passed
        if key is not None:
            self.set_key(key)

        # validate block size
        self._validate_block_size()

        # set iv if passed
        if iv is not None:
            self.set_iv(iv)

    def _validate_block_size(self):
        raise NotImplementedError('Provide the definition of method validating block size')

    def _validate_key_size(self):
        raise NotImplementedError('Provide the definition of method validating key size')

    def _key_schedule(self):
        raise NotImplementedError('Provide the definition of key schedule method')

    def get_round_key(self, round_no: int) -> Any:
        if self._round_key is None:
            raise ValueError('Key is not set')
        return self._round_key[round_no]

    def set_key(self, key: Union[str, np.ndarray]):
        self.key = key
        self._key = Utility.copy_to_numpy(key, error_msg='Invalid key')
        self._round_key = None

        # validate the given key
        self._validate_key_size()

        # calculate round keys
        self._key_schedule()

    def set_iv(self, iv: Union[str, np.ndarray]):
        self.iv = iv
        self._iv = Utility.copy_to_numpy(iv, error_msg='Invalid Initialization Vector')

        # validate the iv length
        if self._block_size != len(self._iv):
            raise ValueError(f'{self._iv} is not a valid block size')

    def encrypt_one_block(self, buffer: np.ndarray) -> np.ndarray:
        raise NotImplementedError('Provide the definition of encrypt method for one block')

    def decrypt_one_block(self, buffer: np.ndarray) -> np.ndarray:
        raise NotImplementedError('Provide the definition of encrypt method for one block')

    def encrypt(self, input_data: Union[str, np.ndarray], output_data: np.ndarray = None,
                mode: SymmetricModesOfOperation = SymmetricModesOfOperation.ECB,
                final: bool = True, pad: Padding = Padding.M0) -> Union[str, np.ndarray]:
        if mode != SymmetricModesOfOperation.ECB:
            raise NotImplementedError('Yet to be implemented')

        if pad != Padding.M0:
            raise NotImplementedError('Yet to be implemented')

        output_data = Utility.copy_to_numpy(input_data, out_data=output_data, error_msg='Invalid plaintext')

        if len(output_data) % self._block_size:
            raise ValueError(f'Input data is not multiple of block length ({self._block_size} bytes)')

        no_of_blocks = len(output_data) // self._block_size

        for i in range(no_of_blocks):
            _start = i * no_of_blocks
            _end = _start + self._block_size
            output_data[_start: _end] = self.encrypt_one_block(output_data[_start: _end])

        if isinstance(input_data, str):
            output_data = Utility.convert_to_str(output_data)

        return output_data

    def decrypt(self, input_data: Union[str, np.ndarray], output_data: np.ndarray = None,
                mode: SymmetricModesOfOperation = SymmetricModesOfOperation.ECB,
                final: bool = True, pad: Padding = Padding.M0) -> Union[str, np.ndarray]:
        output_data = Utility.copy_to_numpy(input_data, out_data=output_data, error_msg='Invalid ciphertext')

        if len(output_data) % self._block_size:
            raise ValueError(f'Input data is not multiple of block length ({self._block_size} bytes)')

        no_of_blocks = len(output_data) // self._block_size

        for i in range(no_of_blocks):
            _start = i * no_of_blocks
            _end = _start + self._block_size
            output_data[_start: _end] = self.decrypt_one_block(output_data[_start: _end])

        if isinstance(input_data, str):
            output_data = Utility.convert_to_str(output_data)

        return output_data
