# import external library
import numpy as np

# from import external library
from typing import Union, Tuple

# from import internal library
from block_cipher_modes import SymmetricAlgorithm, \
    BlockCipherConfidentialityModes, BlockCipherAuthenticationModes
from aead import AEAD


class GCM(AEAD):
    # NIST SP800-38D

    def __init__(
            self,
            algorithm: SymmetricAlgorithm,
            key: Union[str, np.ndarray],
            iv: Union[str, np.ndarray],
            payload_bit_length: int,
            mac_length: int,
            associated_data: Union[str, np.ndarray] = ''
    ):
        super(GCM, self).__init__(
            algorithm=algorithm,
            confidential_mode=BlockCipherConfidentialityModes.CTR,
            authentication_mode=BlockCipherAuthenticationModes.GMAC,
            key=key,
            iv=iv,
            payload_bit_length=payload_bit_length,
            mac_length=mac_length,
            associated_data=associated_data
        )

        self.authenticate_output_data = True

    def _validate_algorithm(self):
        if self.algorithm.name not in ('AES',):
            # Section 5.1: Underlying Block Cipher Algorithm
            raise ValueError('For GCM, the block size of the block cipher algorithm shall be 128 bits.'
                             'Currently, the AES algorithm is the only approved block cipher algorithm '
                             'with this block size')

    def _perform_algorithm_specific_operation(self):
        pass

    def _get_associated_data_length(self) -> int:
        # calculate block size for β(N, A)

        # len(A) || A
        block_length = ((self.a + (self._block_size - 1)) // self._block_size) * self._block_size

        return block_length

    @staticmethod
    def _set_length(buffer: np.ndarray, length: int):
        i = len(buffer) - 1
        while length:
            buffer[i] = length & 0xFF
            length >>= 8
            i -= 1

    def _set_payload_length_string(self):
        self.A_C = np.zeros((self._block_size,), dtype=np.uint8)
        self._set_length(self.A_C[:self._block_size // 2], self.a * 8)
        self._set_length(self.A_C[self._block_size // 2:], self.c * 8)

    def _encode_block(self):
        self.block[:self.a] = self.associated_data[:]

    def _final_block_special_handling(
            self,
            output_data: Union[str, np.ndarray],
            mac: Union[str, np.ndarray]
    ) -> Tuple[Union[str, np.ndarray], Union[str, np.ndarray]]:
        _mac = self.authentication.generate(self.A_C, True)
        return output_data, _mac

    def _encode_counter_zero(self):
        if len(self.iv) == 12:
            self.counter[:12] = self.iv[:]
            self.counter[-1] = 0x01
        else:
            raise NotImplementedError

    def _format_counter_block(self, iv: np.ndarray):
        self.c = self.p
        self._set_payload_length_string()

        # formatting of the Counter Blocks
        self.iv = iv
        self._encode_counter_zero()

    def generate_encrypt(
            self,
            payload: Union[str, np.ndarray],
            ciphertext: np.ndarray = None,
            mac: np.ndarray = None,
            final: bool = False
    ) -> Union[Tuple[str, str], Tuple[np.ndarray, np.ndarray]]:
        _ciphertext = super(GCM, self).generate_encrypt(
            payload,
            ciphertext,
            mac,
            final
        )

        if isinstance(_ciphertext, str):
            index = self._block_size * 2
        else:
            index = self._block_size

        return _ciphertext[:-index], _ciphertext[-index:]

    def decrypt_verify(
            self,
            ciphertext: Union[str, np.ndarray],
            mac: Union[str, np.ndarray] = None,
            payload: np.ndarray = None,
            final: bool = False
    ) -> Union[str, np.ndarray]:
        return super(GCM, self).decrypt_verify(
            ciphertext,
            mac,
            payload,
            final
        )


if __name__ == '__main__':
    # AES: https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
    _key = '00000000000000000000000000000000'
    _payload = '00000000000000000000000000000000'
    _iv = '000000000000000000000000'
    _associated_data = ''

    print('Scenario 0: AES')
    print(f'Key {_key}')
    print(f'IV {_iv}')
    print(f'Payload {_payload}')
    print(f'Associated Data {_associated_data}')

    # print('-' * 80)
    # print('Mode : GCM')
    # aes = GCM(SymmetricAlgorithm.AES, _key, _iv, 16 * 8, 16, _associated_data)
    # _ciphertext_, _mac = aes.generate_encrypt(_payload, final=True)
    # print(f'Ciphertext + MAC {_ciphertext_, _mac}')
    # if _ciphertext_ != '0388dace60b6a392f328c2b971b2fe78'.upper():
    #     raise RuntimeError('AES GCM generate_encrypt ciphertext fails')
    # if _mac != 'ab6e47d42cec13bdf53a67b21257bddf'.upper():
    #     raise RuntimeError('AES GCM generate_encrypt mac fails')

    # AES
    _key = 'A43983414EA1090A6153B4F8ACFD06E9'
    _payload = '12A8A94383913B3436C44432EED44DABF945AFD13F5F6EAC2D096274B6F6A4'
    _iv = 'A99D5BD72A296F649FCF1BE1'
    _associated_data = '0001020304050607'

    print('Scenario 1: AES')
    print(f'Key {_key}')
    print(f'IV {_iv}')
    print(f'Payload {_payload}')
    print(f'Associated Data {_associated_data}')

    print('-' * 80)
    print('Mode : GCM')
    aes = GCM(SymmetricAlgorithm.AES, _key, _iv, 31 * 8, 16, _associated_data)
    _ciphertext_, _mac = aes.generate_encrypt(_payload, final=True)
    print(f'Ciphertext + MAC {_ciphertext_, _mac}')
    if _ciphertext_ != '4DB9E15D5FA37B732601C15EF19197DBC31E74A255A494957A939D043D2AC9'.upper():
        raise RuntimeError('AES GCM generate_encrypt ciphertext fails')
    if _mac != '3B15E3440E0AE755AFA02A7E99EAF022'.upper():
        raise RuntimeError('AES GCM generate_encrypt mac fails')

    aes = GCM(SymmetricAlgorithm.AES, _key, _iv, 31 * 8, 16, _associated_data)
    _payload_out = aes.decrypt_verify(_ciphertext_, _mac, final=True)
    print(f'Payload {_payload_out}')
    if _payload_out != _payload.upper():
        raise RuntimeError('AES GCM decrypt_verify fails')

    _iv = 'A99D5BD72A296F649FCF1BE112'
    print('Scenario 2: AES')
    print(f'Key {_key}')
    print(f'IV {_iv}')
    print(f'Payload {_payload}')
    print(f'Associated Data {_associated_data}')

    print('-' * 80)
    print('Mode : GCM')
    aes = GCM(SymmetricAlgorithm.AES, _key, _iv, 31 * 8, 16, _associated_data)
    _ciphertext_, _mac = aes.generate_encrypt(_payload, final=True)
    print(f'Ciphertext + MAC {_ciphertext_, _mac}')
    if _ciphertext_ != '86ECF1D3A0FA4A78F20E558EF97CEB597CCAC365A1D8CE7B34739DA55F2627'.upper():
        raise RuntimeError('AES GCM generate_encrypt fails')
    if _mac != '3FCC4392249C6D493CB935623A02A8FC'.upper():
        raise RuntimeError('AES GCM generate_encrypt fails')

    aes = GCM(SymmetricAlgorithm.AES, _key, _iv, 31 * 8, 16, _associated_data)
    _payload_out = aes.decrypt_verify(_ciphertext_, _mac, final=True)
    print(f'Payload {_payload_out}')
    if _payload_out != _payload.upper():
        raise RuntimeError('AES GCM decrypt_verify fails')
