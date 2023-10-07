# import external library
import numpy as np

# from import external library
from typing import Optional, Union

# from import internal library
from bitwise import Bitwise
from block_cipher_modes import SymmetricAlgorithm, AEADModes
from block_cipher import BlockCipher
from mac import MessageAuthenticationCode
from padding import Padding, PaddingScheme
from utility import Utility


class AEAD:
    def __init__(
            self,
            algorithm: SymmetricAlgorithm,
            mode: AEADModes,
            iv: Optional[Union[str, np.ndarray]] = None
    ):
        # Authenticated Encryption with Additional Data
        # create an algorithm instance
        BlockCipher(algorithm)
        self.algorithm = algorithm.value()
        self._block_size = self.algorithm.get_block_size()
        self.encrypt_one_block = self.algorithm.get_encrypt_method()
        self.decrypt_one_block = self.algorithm.get_decrypt_method()

        # verify and store mode
        AEADModes(mode)
        self.mode = mode
        self.is_chaining = bool(mode.value & BlockCipherModesOfOperation.CHAINING_BIT)
        self.block_cipher = mode.value & BlockCipherModesOfOperation.BLOCK_CIPHER
        self.stream_cipher = mode.value & BlockCipherModesOfOperation.STREAM_CIPHER

        # store iv and initialize iv (numpy array)
        self.iv = iv
        self._iv = None

        # set iv (numpy array) if passed
        if iv is not None:
            self.set_iv(iv)

        # verify and store pad
        PaddingScheme(pad)
        self.pad = pad

        # create padding object
        self.padding = Padding(pad)

        # working numpy buffer
        self.src_temp = np.zeros((self._block_size,), dtype=np.uint8)

    def generate_encrypt(
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

        if self.is_chaining and self._iv is None:
            raise ValueError('IV is not set')

        # calculate number of complete blocks
        no_of_blocks = len(output_data) // self._block_size

        # process each block
        for i in range(no_of_blocks):
            _start = i * self._block_size
            _end = _start + self._block_size

            if self.is_chaining:
                if self.stream_cipher:
                    self.src_temp[:] = self._iv[:]
                elif self.block_cipher:
                    self.src_temp[:] = output_data[_start: _end]
                    Bitwise.xor(self.src_temp, self._iv, self.src_temp)
                else:
                    pass
            else:
                self.src_temp[:] = output_data[_start: _end]

            self.encrypt_one_block(self.src_temp)

            if self.is_chaining:
                if self.mode == BlockCipherConfidentialityModes.CBC:
                    output_data[_start: _end] = self.src_temp[:]
                    self._iv[:] = output_data[_start: _end]
                elif self.stream_cipher:
                    Bitwise.xor(self.src_temp, output_data[_start: _end], output_data[_start: _end])
                    if self.mode == BlockCipherConfidentialityModes.OFB:
                        self._iv[:] = self.src_temp[:]
                    elif self.mode == BlockCipherConfidentialityModes.CFB:
                        self._iv[:] = output_data[_start: _end]
                    elif self.mode == BlockCipherConfidentialityModes.CTR:
                        self._increment_iv()
                    else:
                        pass
                else:
                    pass
            else:
                output_data[_start: _end] = self.src_temp[:]

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

        if self.is_chaining and self._iv is None:
            raise ValueError('IV is not set')

        # calculate number of complete blocks
        no_of_blocks = len(output_data) // self._block_size

        # process each block
        for i in range(no_of_blocks):
            _start = i * self._block_size
            _end = _start + self._block_size

            if self.is_chaining:
                if self.stream_cipher:
                    self.src_temp[:] = self._iv[:]
                elif self.block_cipher:
                    self.src_temp[:] = output_data[_start: _end]
                else:
                    pass
            else:
                self.src_temp[:] = output_data[_start: _end]

            if self.stream_cipher:
                self.encrypt_one_block(self.src_temp)
            else:
                self.decrypt_one_block(self.src_temp)

            if self.is_chaining:
                if self.mode == BlockCipherConfidentialityModes.CBC:
                    Bitwise.xor(self.src_temp, self._iv, self.src_temp)
                    self._iv[:] = output_data[_start: _end]
                    output_data[_start: _end] = self.src_temp[:]
                elif self.stream_cipher:
                    if self.mode == BlockCipherConfidentialityModes.OFB:
                        self._iv[:] = self.src_temp[:]
                    elif self.mode == BlockCipherConfidentialityModes.CFB:
                        self._iv[:] = output_data[_start: _end]
                    elif self.mode == BlockCipherConfidentialityModes.CTR:
                        self._increment_iv()
                    else:
                        pass
                    Bitwise.xor(self.src_temp, output_data[_start: _end], output_data[_start: _end])
                else:
                    pass
            else:
                output_data[_start: _end] = self.src_temp[:]

        # remove padding in final call
        if final:
            output_data = self.padding.remove_padding(output_data)

        # return output in same format as input
        if isinstance(input_data, str):
            output_data = Utility.convert_to_str(output_data)

        return output_data


if __name__ == '__main__':
    # AES
    _key = 'A43983414EA1090A6153B4F8ACFD06E9'
    _input_data = '12A8A94383913B3436C44432EED44DABF945AFD13F5F6EAC2D096274B6F6A422'
    _iv = 'A99D5BD72A296F649FCF1BE12BA2290E'

    print('Scenario 1: AES')
    print(f'Key {_key}')
    print(f'IV {_iv}')
    print(f'Plaintext {_input_data}')

    print('-' * 80)
    print('Mode : CCM')
    aes = AEAD(AEADModes.CCM)
    aes.set_key(_key)
    _output_data = aes.generate_mac(_input_data, final=True)
    print(f'MAC {_output_data}')
    if _output_data != '6DB32EE1C72165CBE903039D5CC9C5B3':
        raise RuntimeError('AES CBC-MAC fails')
