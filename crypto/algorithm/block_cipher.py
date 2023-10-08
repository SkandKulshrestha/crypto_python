# import external library
import numpy as np

# from import external library
from typing import Optional, Union

# from import internal library
from bitwise import Bitwise
from block_cipher_modes import SymmetricAlgorithm, \
    BlockCipherConfidentialityModes, BlockCipherModesOfOperation
from padding import Padding, PaddingScheme
from utility import Utility


class BlockCipher:
    def __init__(
            self,
            algorithm: SymmetricAlgorithm,
            mode: BlockCipherConfidentialityModes = BlockCipherConfidentialityModes.ECB,
            pad: PaddingScheme = PaddingScheme.M1,
            iv: Optional[Union[str, np.ndarray]] = None
    ):
        # create an algorithm instance
        SymmetricAlgorithm(algorithm)
        self.algorithm = algorithm.value()
        self._block_size = self.algorithm.get_block_size()
        self.encrypt_one_block = self.algorithm.get_encrypt_method()
        self.decrypt_one_block = self.algorithm.get_decrypt_method()

        # verify and store mode
        BlockCipherConfidentialityModes(mode)
        self.mode = mode
        self.is_chaining = bool(mode.value & BlockCipherModesOfOperation.CHAINING_BIT)
        self.block_cipher = mode.value & BlockCipherModesOfOperation.BLOCK_CIPHER
        self.stream_cipher = mode.value & BlockCipherModesOfOperation.STREAM_CIPHER

        # verify and store pad
        PaddingScheme(pad)
        self.pad = pad

        # create padding object
        self.padding = Padding(pad, self._block_size)

        # store iv and initialize iv (numpy array)
        self.iv = iv
        self._iv = None

        # set iv (numpy array) if passed
        if iv is not None:
            self.set_iv(iv)

        # working numpy buffer
        self.src_temp = np.zeros((self._block_size,), dtype=np.uint8)

    def _increment_iv(self):
        # get last index
        i = len(self._iv) - 1

        # iterate from last, until +1 have no impact on the previous byte
        while self._iv[i] == 0xFF:
            # adding 1 and carry is populated in next operation
            self._iv[i] = 0x00
            i -= 1

        # add 1
        self._iv[i] += 1

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
        _output_data = Utility.copy_to_numpy(input_data, out_data=output_data, error_msg='Invalid plaintext')

        # append padding in final call
        if final:
            end_index = len(_output_data)
            _output_data = self.padding.apply_padding(_output_data)
        else:
            _output_data = _output_data
            end_index = len(_output_data)

        if len(_output_data) % self._block_size:
            raise ValueError(f'Input data is not multiple of block length ({self._block_size} bytes).'
                             'Padding will only be handled in final call')

        if self.is_chaining and self._iv is None:
            raise ValueError('IV is not set')

        # calculate number of complete blocks
        no_of_blocks = len(_output_data) // self._block_size

        # process each block
        for i in range(no_of_blocks):
            _start = i * self._block_size
            _end = _start + self._block_size

            if self.is_chaining:
                if self.stream_cipher:
                    self.src_temp[:] = self._iv[:]
                elif self.block_cipher:
                    self.src_temp[:] = _output_data[_start: _end]
                    Bitwise.xor(self.src_temp, self._iv, self.src_temp)
                else:
                    pass
            else:
                self.src_temp[:] = _output_data[_start: _end]

            self.encrypt_one_block(self.src_temp)

            if self.is_chaining:
                if self.mode == BlockCipherConfidentialityModes.CBC:
                    _output_data[_start: _end] = self.src_temp[:]
                    self._iv[:] = _output_data[_start: _end]
                elif self.stream_cipher:
                    Bitwise.xor(self.src_temp[:], _output_data[_start: _end], _output_data[_start: _end])

                    if self.mode == BlockCipherConfidentialityModes.OFB:
                        self._iv[:] = self.src_temp[:]
                    elif self.mode == BlockCipherConfidentialityModes.CFB:
                        self._iv[:] = _output_data[_start: _end]
                    elif self.mode == BlockCipherConfidentialityModes.CTR:
                        self._increment_iv()
                    else:
                        pass
                else:
                    pass
            else:
                _output_data[_start: _end] = self.src_temp[:]

        if final and self.stream_cipher:
            if output_data is not None:
                output_data[:] = _output_data[:end_index]

        # return output in same format as input
        if isinstance(input_data, str):
            return Utility.convert_to_str(_output_data[:end_index])

        return _output_data[:end_index]

    def decrypt(
            self,
            input_data: Union[str, np.ndarray],
            output_data: np.ndarray = None,
            final: bool = False
    ) -> Union[str, np.ndarray]:
        # copy input to output for further calculation
        _output_data = Utility.copy_to_numpy(input_data, out_data=output_data, error_msg='Invalid ciphertext')

        end_index = len(_output_data)
        if self.stream_cipher:
            _output_data = Padding(PaddingScheme.M1, self._block_size).apply_padding(_output_data)

        # validate input data length
        if len(_output_data) % self._block_size:
            raise ValueError(f'Input data is not multiple of block length ({self._block_size} bytes)')

        if self.is_chaining and self._iv is None:
            raise ValueError('IV is not set')

        # calculate number of complete blocks
        no_of_blocks = len(_output_data) // self._block_size

        # process each block
        for i in range(no_of_blocks):
            _start = i * self._block_size
            _end = _start + self._block_size

            if self.is_chaining:
                if self.stream_cipher:
                    self.src_temp[:] = self._iv[:]
                elif self.block_cipher:
                    self.src_temp[:] = _output_data[_start: _end]
                else:
                    pass
            else:
                self.src_temp[:] = _output_data[_start: _end]

            if self.stream_cipher:
                self.encrypt_one_block(self.src_temp)
            else:
                self.decrypt_one_block(self.src_temp)

            if self.is_chaining:
                if self.mode == BlockCipherConfidentialityModes.CBC:
                    Bitwise.xor(self.src_temp, self._iv, self.src_temp)
                    self._iv[:] = _output_data[_start: _end]
                    _output_data[_start: _end] = self.src_temp[:]
                elif self.stream_cipher:
                    if self.mode == BlockCipherConfidentialityModes.OFB:
                        self._iv[:] = self.src_temp[:]
                    elif self.mode == BlockCipherConfidentialityModes.CFB:
                        self._iv[:] = _output_data[_start: _end]
                    elif self.mode == BlockCipherConfidentialityModes.CTR:
                        self._increment_iv()
                    else:
                        pass
                    Bitwise.xor(self.src_temp, _output_data[_start: _end], _output_data[_start: _end])
                else:
                    pass
            else:
                _output_data[_start: _end] = self.src_temp[:]

        # remove padding in final call
        if final:
            _output_data = self.padding.remove_padding(_output_data)

        if output_data is not None:
            output_data[:] = _output_data[:end_index]

        # return output in same format as input
        if isinstance(input_data, str):
            return Utility.convert_to_str(_output_data[:end_index])

        return _output_data[:end_index]


if __name__ == '__main__':
    import warnings
    from warning_crypto import WithdrawnWarning

    # DES
    _key = '133457799BBCDFF1'
    _input_data = '0123456789ABCDEF'
    print('Scenario 1: DES')
    print(f'Key {_key}')
    print(f'Plaintext {_input_data}')
    des = BlockCipher(SymmetricAlgorithm.DES)
    warnings.filterwarnings("ignore", category=WithdrawnWarning)
    des.set_key(_key)
    warnings.resetwarnings()
    _output_data_ = des.encrypt(_input_data)
    print(f'Ciphertext {_output_data_}')
    if _output_data_ != '85E813540F0AB405':
        raise RuntimeError('DES encryption fails')

    _output_data_ = des.decrypt(_output_data_)
    print(f'Plaintext {_output_data_}')
    if _output_data_ != _input_data:
        raise RuntimeError('DES decryption fails')

    # AES
    _key = '5468617473206D79204B756E67204675'
    _input_data = '54776F204F6E65204E696E652054776F'
    print('Scenario 2: AES')
    print(f'Key {_key}')
    print(f'Plaintext {_input_data}')
    aes = BlockCipher(SymmetricAlgorithm.AES)
    aes.set_key(_key)
    _output_data_ = aes.encrypt(_input_data)
    print(f'Ciphertext {_output_data_}')
    if _output_data_ != '29C3505F571420F6402299B31A02D73A':
        raise RuntimeError('AES encryption fails')

    _output_data_ = aes.decrypt(_output_data_)
    print(f'Plaintext {_output_data_}')
    if _output_data_ != _input_data:
        raise RuntimeError('AES decryption fails')

    # AES
    _key = 'A43983414EA1090A6153B4F8ACFD06E9'
    _input_data = '12A8A94383913B3436C44432EED44DABF945AFD13F5F6EAC2D096274B6F6A422'
    _iv = 'A99D5BD72A296F649FCF1BE12BA2290E'
    print('=' * 80)
    print('Scenario 3: AES, Pad=M0')
    print(f'Key {_key}')
    print(f'IV {_iv}')
    print(f'Plaintext {_input_data}')

    print('-' * 80)
    print('Mode : ECB')
    aes = BlockCipher(SymmetricAlgorithm.AES, BlockCipherConfidentialityModes.ECB, PaddingScheme.M1, _iv)
    aes.set_key(_key)
    _output_data_ = aes.encrypt(_input_data, final=True)
    print(f'Ciphertext {_output_data_}')
    if _output_data_ != '66D215FFBEB87FE36D46FDA1952CB980AE44DC9C0446B53D3A4A3D167AC80C3C':
        raise RuntimeError('AES encryption fails')
    _output_data_ = aes.decrypt(_output_data_)
    print(f'Plaintext {_output_data_}')
    if _output_data_ != _input_data:
        raise RuntimeError('AES decryption fails')

    print('-' * 80)
    print('Mode : CBC')
    aes = BlockCipher(SymmetricAlgorithm.AES, BlockCipherConfidentialityModes.CBC, PaddingScheme.M1, _iv)
    aes.set_key(_key)
    _output_data_ = aes.encrypt(_input_data, final=True)
    print(f'Ciphertext {_output_data_}')
    if _output_data_ != '08F2642434B1BDB12CFA8C08AF981F078159377AB3FEBBBCCE0ACA0263805124':
        raise RuntimeError('AES encryption fails')
    aes.set_iv(_iv)
    _output_data_ = aes.decrypt(_output_data_)
    print(f'Plaintext {_output_data_}')
    if _output_data_ != _input_data:
        raise RuntimeError('AES decryption fails')

    _input_data = _input_data[:-2]
    print('-' * 80)
    print('Mode : OFB')
    aes = BlockCipher(SymmetricAlgorithm.AES, BlockCipherConfidentialityModes.OFB, PaddingScheme.M1, _iv)
    aes.set_key(_key)
    _output_data_ = aes.encrypt(_input_data, final=True)
    print(f'Ciphertext {_output_data_}')
    if _output_data_ != '1D692DFC5101603D3EFEA4C1AEF3B91CCB6CF65C6EB3284B4893C53A566801':
        raise RuntimeError('AES encryption fails')
    aes.set_iv(_iv)
    _output_data_ = aes.decrypt(_output_data_)
    print(f'Plaintext {_output_data_}')
    if _output_data_ != _input_data:
        raise RuntimeError('AES decryption fails')

    print('-' * 80)
    print('Mode : CFB')
    aes = BlockCipher(SymmetricAlgorithm.AES, BlockCipherConfidentialityModes.CFB, PaddingScheme.M1, _iv)
    aes.set_key(_key)
    _output_data_ = aes.encrypt(_input_data, final=True)
    print(f'Ciphertext {_output_data_}')
    if _output_data_ != '1D692DFC5101603D3EFEA4C1AEF3B91C0A86A84EF8F8B3B0A06CA0534907DD':
        raise RuntimeError('AES encryption fails')
    aes.set_iv(_iv)
    _output_data_ = aes.decrypt(_output_data_)
    print(f'Plaintext {_output_data_}')
    if _output_data_ != _input_data:
        raise RuntimeError('AES decryption fails')

    print('-' * 80)
    print('Mode : CTR')
    aes = BlockCipher(SymmetricAlgorithm.AES, BlockCipherConfidentialityModes.CTR, PaddingScheme.M1, _iv)
    aes.set_key(_key)
    _output_data_ = aes.encrypt(_input_data, final=True)
    print(f'Ciphertext {_output_data_}')
    if _output_data_ != '1D692DFC5101603D3EFEA4C1AEF3B91CC56829EFB73A01BEDBE82E3879476A':
        raise RuntimeError('AES encryption fails')
    aes.set_iv(_iv)
    _output_data_ = aes.decrypt(_output_data_)
    print(f'Plaintext {_output_data_}')
    if _output_data_ != _input_data:
        raise RuntimeError('AES decryption fails')
