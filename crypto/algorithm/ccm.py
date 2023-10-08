# import external library
import numpy as np

# from import external library
from typing import Union

# from import internal library
from block_cipher_modes import SymmetricAlgorithm, \
    BlockCipherConfidentialityModes, BlockCipherAuthenticationModes
from aead import AEAD


class CCM(AEAD):
    # NIST SP800-38C

    def __init__(
            self,
            algorithm: SymmetricAlgorithm,
            key: Union[str, np.ndarray],
            nonce: Union[str, np.ndarray],
            payload_bit_length: int,
            mac_length: int,
            associated_data: Union[str, np.ndarray] = ''
    ):
        super(CCM, self).__init__(
            algorithm=algorithm,
            confidential_mode=BlockCipherConfidentialityModes.CTR,
            authentication_mode=BlockCipherAuthenticationModes.CBC_MAC,
            key=key,
            iv=nonce,
            payload_bit_length=payload_bit_length,
            mac_length=mac_length,
            associated_data=associated_data
        )

    def _validate_algorithm(self):
        if self.algorithm.name not in ('AES',):
            # Section 5.1: Underlying Block Cipher Algorithm
            raise ValueError('For CCM, the block size of the block cipher algorithm shall be 128 bits.'
                             'Currently, the AES algorithm is the only approved block cipher algorithm '
                             'with this block size')

    def _perform_algorithm_specific_operation(self):
        # Appendix A.1: Length Requirements
        if self.t not in (4, 6, 8, 10, 12, 14, 16):
            raise ValueError('Length of mac, i.e., t is an element of {4, 6, 8, 10, 12, 14, 16}.')

    def _get_associated_data_length(self) -> int:
        # calculate block size for β(N, A)

        # len(A) || A
        if 0 < self.a < ((1 << 16) - (1 << 8)):
            info_len = 2
        elif ((1 << 16) - (1 << 8)) < self.a < (1 << 32):
            info_len = 6
        elif (1 << 32) < self.a < (1 << 64):
            info_len = 10
        else:
            raise ValueError(f'Formatting not defined for a = {self.a}')
        block_length = (((self.a + info_len) + (self._block_size - 1)) // self._block_size) * self._block_size

        # added for block zero
        block_length += self._block_size

        return block_length

    @staticmethod
    def _set_length(buffer: np.ndarray, length: int):
        i = len(buffer) - 1
        while length:
            buffer[i] = length & 0xFF
            length >>= 8
            i -= 1

    def _set_payload_length_string(self):
        self.Q = np.zeros((self.q,), dtype=np.uint8)
        self._set_length(self.Q, self.p)

    def _encode_block_zero(self):
        # Appendix A.2.1: Formatting of the Control Information and the Nonce
        reserved = 0
        adata = 1 if self.a else 0
        encode_t = (self.t - 2) // 2
        encode_q = self.q - 1
        flag = (reserved << 7) | (adata << 6) | (encode_t << 3) | encode_q

        block0 = self.block[0:16]

        block0[0] = flag
        block0[1: 16 - self.q] = self.nonce[:]
        block0[16 - self.q: 16] = self.Q[:]

    def _encode_associated_data_block(self):
        # Appendix A.2.2: Formatting of the Associated Data
        block = self.block[16:]
        info_start_index = 2
        info_end_index = 2

        if 0 < self.a < ((1 << 16) - (1 << 8)):
            info_start_index = 0
        elif ((1 << 16) - (1 << 8)) < self.a < (1 << 32):
            block[0] = 0xFF
            block[1] = 0xFE
            info_end_index = 6
        elif (1 << 32) < self.a < (1 << 64):
            block[0] = 0xFF
            block[1] = 0xFF
            info_end_index = 10
        else:
            raise ValueError(f'Formatting not defined for a = {self.a}')

        self._set_length(block[info_start_index:info_end_index], self.a)
        block[info_end_index:info_end_index + self.a] = self.associated_data[:]

    def _encode_block(self):
        # Appendix A.2: Formatting of the Input Data
        # Appendix A.2.1: Formatting of the Control Information and the Nonce
        self._encode_block_zero()

        # Appendix A.2.2: Formatting of the Associated Data
        self._encode_associated_data_block()

    def _encode_counter_zero(self):
        # Appendix A.3: Formatting of the Counter Blocks
        reserved = 0
        encode_q = self.q - 1
        flag = (reserved << 6) | encode_q

        self.counter[0] = flag
        self.counter[1:16 - self.q] = self.nonce[:]

    def _format_counter_block(self, nonce: np.ndarray):
        # Appendix A.1: Length Requirements
        # validate n
        self.n = len(nonce)
        # TODO: SCV manager is supporting 1 byte long nonce!
        if self.n not in (7, 8, 9, 10, 11, 12, 13):
            raise ValueError('Length of nonce, i.e., n is an element of {7, 8, 9, 10, 11, 12, 13}.')

        # compute and validate q
        q = 15 - self.n
        self.q = q
        if self.p > (1 << (8 * q)):
            raise ValueError('Length of nonce is invalid as payload length cannot be encoded.')
        self._set_payload_length_string()

        # Appendix A.3: Formatting of the Counter Blocks
        self.nonce = nonce
        self._encode_counter_zero()

    def generate_encrypt(
            self,
            payload: Union[str, np.ndarray],
            ciphertext: np.ndarray = None,
            mac: np.ndarray = None,
            final: bool = False
    ) -> Union[str, np.ndarray]:
        return super(CCM, self).generate_encrypt(
            payload,
            ciphertext,
            mac,
            final
        )

    def decrypt_verify(
            self,
            ciphertext: Union[str, np.ndarray],
            payload: np.ndarray = None,
            final: bool = False
    ) -> Union[str, np.ndarray]:
        return super(CCM, self).decrypt_verify(
            ciphertext,
            payload,
            final
        )


if __name__ == '__main__':
    # AES
    _key = '404142434445464748494a4b4c4d4e4f'
    _payload = '20212223'
    _nonce = '10111213141516'
    _associated_data = '0001020304050607'

    print('Scenario 1: AES')
    print(f'Key {_key}')
    print(f'Nonce {_nonce}')
    print(f'Payload {_payload}')
    print(f'Associated Data {_associated_data}')

    print('-' * 80)
    print('Mode : CCM')
    aes = CCM(SymmetricAlgorithm.AES, _key, _nonce, 32, 4, _associated_data)
    ciphertext_mac = aes.generate_encrypt(_payload, final=True)
    print(f'Ciphertext + MAC {ciphertext_mac}')
    if ciphertext_mac != '7162015b4dac255d'.upper():
        raise RuntimeError('AES CCM generate_encrypt fails')

    aes = CCM(SymmetricAlgorithm.AES, _key, _nonce, 32, 4, _associated_data)
    _payload_out = aes.decrypt_verify(ciphertext_mac, final=True)
    print(f'Payload {_payload_out}')
    if _payload_out != _payload.upper():
        raise RuntimeError('AES CCM decrypt_verify fails')

    _payload = '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
    _nonce = '101112131415161718191a1b1c'
    _associated_data = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' \
                       '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f' \
                       '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f' \
                       '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f' \
                       '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f' \
                       'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf' \
                       'c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf' \
                       'e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff' * 256

    print('=' * 80)
    print('Scenario 2: AES')
    print(f'Key {_key}')
    print(f'Nonce {_nonce}')
    print(f'Payload {_payload}')
    # print(f'Associated Data {_associated_data}')

    print('-' * 80)
    print('Mode : CCM')
    aes = CCM(SymmetricAlgorithm.AES, _key, _nonce, 256, 14, _associated_data)
    ciphertext_mac = aes.generate_encrypt(_payload, final=True)
    print(f'Ciphertext + MAC {ciphertext_mac}')
    if ciphertext_mac != '69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc' \
                         '484828529463ccf72b4ac6bec93e8598e7f0dadbcea5b'.upper():
        raise RuntimeError('AES CCM generate_encrypt fails')

    aes = CCM(SymmetricAlgorithm.AES, _key, _nonce, 256, 14, _associated_data)
    _payload_out = aes.decrypt_verify(ciphertext_mac, final=True)
    print(f'Payload {_payload_out}')
    if _payload_out != _payload.upper():
        raise RuntimeError('AES CCM decrypt_verify fails')
