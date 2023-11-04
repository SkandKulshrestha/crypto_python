# import external library
import numpy as np

# from import external library
from typing import Union, Tuple

# from import internal library
from block_cipher_modes import SymmetricAlgorithm, \
    BlockCipherConfidentialityModes, BlockCipherAuthenticationModes
from aead import AEAD
from ghash import GHASH


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
            ghash = GHASH(self.algorithm)
            ghash.set_key(self.key)
            ghash.generate(self.iv, final=True)
            self._set_length(self.counter[self._block_size // 2:], len(self.iv) * 8)
            ghash.generate(self.counter, final=True, hash_=self.counter)

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
    # Test Case 1
    _key = '00000000000000000000000000000000'
    _payload = ''
    _iv = '000000000000000000000000'
    _associated_data = ''

    print('Test Case 1')
    print(f'Key {_key}')
    print(f'IV {_iv}')
    print(f'Payload {_payload}')
    print(f'Associated Data {_associated_data}')

    print('-' * 80)
    print('Mode : GCM')
    aes = GCM(SymmetricAlgorithm.AES, _key, _iv, 0 * 8, 16, _associated_data)
    _ciphertext_, _mac_ = aes.generate_encrypt(_payload, final=True)
    print(f'Ciphertext + MAC {_ciphertext_, _mac_}')
    if _ciphertext_ != ''.upper():
        raise RuntimeError('AES GCM generate_encrypt ciphertext fails')
    if _mac_ != '58e2fccefa7e3061367f1d57a4e7455a'.upper():
        raise RuntimeError('AES GCM generate_encrypt mac fails')

    aes = GCM(SymmetricAlgorithm.AES, _key, _iv, 0 * 8, 16, _associated_data)
    _payload_out = aes.decrypt_verify(_ciphertext_, _mac_, final=True)
    print(f'Payload {_payload_out}')
    if _payload_out != _payload.upper():
        raise RuntimeError('AES GCM decrypt_verify fails')

    print('=' * 80)

    # Test Case 2
    _key = '00000000000000000000000000000000'
    _payload = '00000000000000000000000000000000'
    _iv = '000000000000000000000000'
    _associated_data = ''

    print('Test Case 2')
    print(f'Key {_key}')
    print(f'IV {_iv}')
    print(f'Payload {_payload}')
    print(f'Associated Data {_associated_data}')

    print('-' * 80)
    print('Mode : GCM')
    aes = GCM(SymmetricAlgorithm.AES, _key, _iv, 16 * 8, 16, _associated_data)
    _ciphertext_, _mac_ = aes.generate_encrypt(_payload, final=True)
    print(f'Ciphertext + MAC {_ciphertext_, _mac_}')
    if _ciphertext_ != '0388dace60b6a392f328c2b971b2fe78'.upper():
        raise RuntimeError('AES GCM generate_encrypt ciphertext fails')
    if _mac_ != 'ab6e47d42cec13bdf53a67b21257bddf'.upper():
        raise RuntimeError('AES GCM generate_encrypt mac fails')

    aes = GCM(SymmetricAlgorithm.AES, _key, _iv, 16 * 8, 16, _associated_data)
    _payload_out = aes.decrypt_verify(_ciphertext_, _mac_, final=True)
    print(f'Payload {_payload_out}')
    if _payload_out != _payload.upper():
        raise RuntimeError('AES GCM decrypt_verify fails')

    print('=' * 80)

    # Test Case 6
    _key = 'feffe9928665731c6d6a8f9467308308'
    _payload = 'd9313225f88406e5a55909c5aff5269a' \
               '86a7a9531534f7da2e4c303d8a318a72' \
               '1c3c0c95956809532fcf0e2449a6b525' \
               'b16aedf5aa0de657ba637b39'
    _iv = '9313225df88406e555909c5aff5269aa' \
          '6a7a9538534f7da1e4c303d2a318a728' \
          'c3c0c95156809539fcf0e2429a6b5254' \
          '16aedbf5a0de6a57a637b39b'
    _associated_data = 'feedfacedeadbeeffeedfacedeadbeef' \
                       'abaddad2'

    print('Test Case 6')
    print(f'Key {_key}')
    print(f'IV {_iv}')
    print(f'Payload {_payload}')
    print(f'Associated Data {_associated_data}')

    print('-' * 80)
    print('Mode : GCM')
    aes = GCM(SymmetricAlgorithm.AES, _key, _iv, 60 * 8, 16, _associated_data)
    _ciphertext_, _mac_ = aes.generate_encrypt(_payload, final=True)
    print(f'Ciphertext + MAC {_ciphertext_, _mac_}')
    if _ciphertext_ != '8ce24998625615b603a033aca13fb894' \
                       'be9112a5c3a211a8ba262a3cca7e2ca7' \
                       '01e4a9a4fba43c90ccdcb281d48c7c6f' \
                       'd62875d2aca417034c34aee5'.upper():
        raise RuntimeError('AES GCM generate_encrypt ciphertext fails')
    if _mac_ != '619cc5aefffe0bfa462af43c1699d050'.upper():
        raise RuntimeError('AES GCM generate_encrypt mac fails')

    aes = GCM(SymmetricAlgorithm.AES, _key, _iv, 60 * 8, 16, _associated_data)
    _payload_out = aes.decrypt_verify(_ciphertext_, _mac_, final=True)
    print(f'Payload {_payload_out}')
    if _payload_out != _payload.upper():
        raise RuntimeError('AES GCM decrypt_verify fails')
