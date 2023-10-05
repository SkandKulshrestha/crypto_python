# import external library
import numpy as np

# from import external library
from enum import Enum, IntEnum
from typing import Optional, Union

# from import internal library
from utility import Utility
from padding import Padding, PaddingScheme

from des import DES
from tdes import TDES
from aes import AES


class BlockCipherModesOfOperation(IntEnum):
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
    CTR = 5,
    # Galois/Counter Mode
    GCM = 6


class SymmetricAlgorithm(Enum):
    DES = DES,
    TDES = TDES,
    AES = AES


class BlockCipher:
    def __init__(
            self,
            algorithm: SymmetricAlgorithm,
            key: Optional[Union[str, np.ndarray]] = None,
            iv: Optional[Union[str, np.ndarray]] = None,
            mode: BlockCipherModesOfOperation = BlockCipherModesOfOperation.ECB,
            pad: PaddingScheme = PaddingScheme.M0
    ):
        # create an algorithm instance
        self.algorithm = algorithm.value[0](key=key)
        self._block_size = self.algorithm.get_block_size()
        self.encrypt_one_block = self.algorithm.get_encrypt()
        self.decrypt_one_block = self.algorithm.get_decrypt()

        # store iv, mode and pad
        self.iv = iv
        self.mode = mode
        self.pad = pad

        # initialize iv (numpy array)
        self._iv = None

        # set iv (numpy array) if passed
        if iv is not None:
            self.set_iv(iv)

        if mode != BlockCipherModesOfOperation.ECB:
            raise NotImplementedError('Yet to be implemented. Coming soon...')

        if pad != PaddingScheme.M0:
            raise NotImplementedError('Yet to be implemented. Coming soon...')

        # create padding object
        self.padding = Padding(pad)

    def set_key(self, key: Union[str, np.ndarray]):
        self.algorithm.set_key(key)

    def set_iv(self, iv: Union[str, np.ndarray]):
        # store iv
        self.iv = iv

        # store iv as numpy array
        self._iv = Utility.copy_to_numpy(iv, error_msg='Invalid Initialization Vector')

        # validate iv length
        if self._block_size != len(self._iv):
            raise ValueError(f'{self._iv} is not a valid block size')

    def encrypt(
            self,
            input_data: Union[str, np.ndarray],
            output_data: np.ndarray = None,
            final: bool = False
    ) -> Union[str, np.ndarray]:

        # copy input to output for further calculation
        output_data = Utility.copy_to_numpy(input_data, out_data=output_data, error_msg='Invalid plaintext')

        # append padding in final call
        if final:
            output_data = self.padding.apply_padding(output_data)

        if len(output_data) % self._block_size:
            raise ValueError(f'Input data is not multiple of block length ({self._block_size} bytes).'
                             'Padding will only be handled in final call')

        # calculate number of complete blocks
        no_of_blocks = len(output_data) // self._block_size

        # process each block
        for i in range(no_of_blocks):
            _start = i * no_of_blocks
            _end = _start + self._block_size
            output_data[_start: _end] = self.encrypt_one_block(output_data[_start: _end])

        # return output in same format as input
        if isinstance(input_data, str):
            return Utility.convert_to_str(output_data)

        return output_data

    def decrypt(
            self,
            input_data: Union[str, np.ndarray],
            output_data: np.ndarray = None,
            final: bool = False
    ) -> Union[str, np.ndarray]:
        # copy input to output for further calculation
        output_data = Utility.copy_to_numpy(input_data, out_data=output_data, error_msg='Invalid ciphertext')

        if len(output_data) % self._block_size:
            raise ValueError(f'Input data is not multiple of block length ({self._block_size} bytes)')

        # calculate number of complete blocks
        no_of_blocks = len(output_data) // self._block_size

        # process each block
        for i in range(no_of_blocks):
            _start = i * no_of_blocks
            _end = _start + self._block_size
            output_data[_start: _end] = self.decrypt_one_block(output_data[_start: _end])

        # remove padding in final call
        if final:
            output_data = self.padding.remove_padding(output_data)

        # return output in same format as input
        if isinstance(input_data, str):
            output_data = Utility.convert_to_str(output_data)

        return output_data


if __name__ == '__main__':
    import warnings
    from warning_crypto import WithdrawnWarning
    _key = '133457799BBCDFF1'
    _input_data = '0123456789ABCDEF'
    print('Scenario 1: DES')
    print(f'Key {_key}')
    print(f'Plaintext {_input_data}')
    des = BlockCipher(SymmetricAlgorithm.DES)
    warnings.filterwarnings("ignore", category=WithdrawnWarning)
    des.set_key(_key)
    warnings.resetwarnings()
    _output_data = des.encrypt(_input_data)
    print(f'Ciphertext {_output_data}')
    if _output_data != '85E813540F0AB405':
        raise RuntimeError('DES encryption fails')

    _output_data = des.decrypt(_output_data)
    print(f'Plaintext {_output_data}')
    if _output_data != _input_data:
        raise RuntimeError('DES decryption fails')
