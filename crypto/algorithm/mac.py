# import external library
import numpy as np

# from import external library
from typing import Union

# from import internal library
from bitwise import Bitwise
from block_cipher_modes import SymmetricAlgorithm, \
    BlockCipherAuthenticationModes, BlockCipherModesOfOperation
from padding import Padding, PaddingScheme
from utility import Utility


class MessageAuthenticationCode:
    def __init__(
            self,
            algorithm: SymmetricAlgorithm,
            mode: BlockCipherAuthenticationModes,
            pad: PaddingScheme = PaddingScheme.M1
    ):
        # create an algorithm instance
        SymmetricAlgorithm(algorithm)
        self.algorithm = algorithm.value()
        self._block_size = self.algorithm.get_block_size()
        self.encrypt_one_block = self.algorithm.get_encrypt_method()

        # verify and store mode
        BlockCipherAuthenticationModes(mode)
        self.mode = mode
        self.mac = mode.value & BlockCipherModesOfOperation.MAC

        # verify and store pad
        PaddingScheme(pad)
        self.pad = pad

        # create padding object
        self.padding = Padding(pad, self._block_size)

        # initialize and set iv (numpy array)
        self.iv = '00' * self._block_size
        self._iv = None
        self.set_iv(self.iv)

        # working numpy buffer
        self.src_temp = np.zeros((self._block_size,), dtype=np.uint8)

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

    def generate(
            self,
            input_data: Union[str, np.ndarray],
            final: bool = False,
            mac: np.ndarray = None,
            mac_length: int = None
    ) -> Union[str, np.ndarray]:
        # copy input to output for further calculation
        output_data = Utility.copy_to_numpy(input_data, error_msg='Invalid plaintext')

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
            _start = i * self._block_size
            _end = _start + self._block_size

            if self.mode == BlockCipherAuthenticationModes.CBC_MAC:
                self.src_temp[:] = output_data[_start: _end]
                Bitwise.xor(self.src_temp, self._iv, self.src_temp)
            else:
                pass

            self.encrypt_one_block(self.src_temp)

            if self.mode == BlockCipherAuthenticationModes.CBC_MAC:
                self._iv[:] = self.src_temp[:]
            else:
                pass

        if final:
            # reduce expected mac length to maximum MAC provided
            if mac_length is None or mac_length > self._block_size or mac_length < 0:
                mac_length = self._block_size

            # copy output in passed output data buffer
            if mac is not None:
                mac[:mac_length] = self._iv[:mac_length]

            # return output in same format as input
            if isinstance(input_data, str):
                return Utility.convert_to_str(self._iv[:mac_length])

            mac = self._iv[:mac_length].copy()
        else:
            if isinstance(input_data, str):
                return ''

        return mac

    def verify(
            self,
            input_data: Union[str, np.ndarray],
            final: bool = False,
            mac: Union[str, np.ndarray] = None
    ) -> bool:
        if final:
            if mac is None:
                return False

            mac_length = Utility.get_byte_length(mac)
            mac_buffer = np.ndarray((mac_length,), dtype=np.uint8)
        else:
            mac_length = None
            mac_buffer = None

        response_mac = self.generate(input_data, final=final, mac=mac_buffer, mac_length=mac_length)

        if final:
            if isinstance(input_data, str) and isinstance(mac, str):
                return response_mac == mac
            else:
                return mac_buffer == mac


if __name__ == '__main__':
    # AES
    _key = 'A43983414EA1090A6153B4F8ACFD06E9'
    _input_data = '12A8A94383913B3436C44432EED44DABF945AFD13F5F6EAC2D096274B6F6A422'
    _iv = 'A99D5BD72A296F649FCF1BE12BA2290E'

    print('Scenario 1: AES')
    print(f'Key {_key}')
    print(f'IV {_iv} if required')
    print(f'Plaintext {_input_data}')

    print('-' * 80)
    print('Mode : CBC-MAC')
    aes = MessageAuthenticationCode(SymmetricAlgorithm.AES, BlockCipherAuthenticationModes.CBC_MAC)
    aes.set_key(_key)
    _output_data = aes.generate(_input_data, final=True)
    print(f'MAC {_output_data}')
    if _output_data != '6DB32EE1C72165CBE903039D5CC9C5B3':
        raise RuntimeError('AES CBC-MAC fails')

    print('-' * 80)
    print('Mode : CBC-MAC')
    aes = MessageAuthenticationCode(SymmetricAlgorithm.AES, BlockCipherAuthenticationModes.CBC_MAC)
    aes.set_key(_key)
    _output_data = aes.generate(_input_data, final=True, mac_length=4)
    print(f'MAC {_output_data}')
    if _output_data != '6DB32EE1':
        raise RuntimeError('AES CBC-MAC generation fails')

    print('-' * 80)
    print('Mode : CBC-MAC')
    aes = MessageAuthenticationCode(SymmetricAlgorithm.AES, BlockCipherAuthenticationModes.CBC_MAC)
    aes.set_key(_key)
    _output = aes.verify(_input_data, final=True, mac=_output_data)
    print(f'MAC verified status: {_output}')
    if not _output:
        raise RuntimeError('AES CBC-MAC verification fails')
