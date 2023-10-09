# import external library
import numpy as np

# from import external library
from abc import ABC
from typing import Union, Tuple

# from import internal library
from bitwise import Bitwise
from block_cipher_modes import SymmetricAlgorithm, \
    BlockCipherConfidentialityModes, BlockCipherAuthenticationModes
from block_cipher import BlockCipher
from ghash import GHASH
from mac import MessageAuthenticationCode
from utility import Utility


class AEAD(ABC):
    def __init__(
            self,
            algorithm: SymmetricAlgorithm,
            confidential_mode: BlockCipherConfidentialityModes,
            authentication_mode: BlockCipherAuthenticationModes,
            key: Union[str, np.ndarray],
            iv: Union[str, np.ndarray],
            payload_bit_length: int,
            mac_length: int,
            associated_data: Union[str, np.ndarray] = ''
    ):
        # Authenticated Encryption with Additional Data
        self.algorithm = algorithm
        self._validate_algorithm()
        self.algorithm_obj = algorithm.value()
        self._block_size = self.algorithm_obj.get_block_size()

        # verify and store mode
        # aead_mode = AEADModes(confidential_mode.value | authentication_mode.value)
        confidential_mode = confidential_mode
        authentication_mode = authentication_mode

        # set payload length
        self.payload_bit_length = payload_bit_length
        self.p = (payload_bit_length + 7) // 8

        # set expected MAC length
        self.t = mac_length

        # set associated data
        self.associated_data = Utility.copy_to_numpy(associated_data, error_msg='Invalid Initialization Vector')
        self.a = Utility.get_byte_length(associated_data)

        # perform algorithm specific operation like validation or setting some parameters
        # as inherited algorithm calls dunder init method of its parent class
        # in the beginning of its dunder init
        self._perform_algorithm_specific_operation()

        # create instances of BlockCipher and MAC
        self.confidential = BlockCipher(algorithm, confidential_mode)
        if authentication_mode == BlockCipherAuthenticationModes.GMAC:
            self.authentication = GHASH(algorithm)
        else:
            self.authentication = MessageAuthenticationCode(algorithm, authentication_mode)

        # set key
        self._set_key(key)

        # set iv
        self.counter = np.zeros((self._block_size,), dtype=np.uint8)
        self._set_iv(iv)

        # allocated blocks to hold the associated data
        associated_data_len = self._get_associated_data_length()
        self.block = np.zeros((associated_data_len,), dtype=np.uint8)

        # apply formatting function on N and A
        self._encode_block()

        # Special handling:
        # perform confidential on first block
        input_data = np.zeros((self._block_size,), dtype=np.uint8)
        self.cipher1 = np.zeros((self._block_size,), dtype=np.uint8)
        self.confidential.encrypt(input_data, self.cipher1)

        # start performing authentication with associated data
        self.authentication.generate(self.block)
        self.authenticate_output_data = False

    def _validate_algorithm(self):
        raise NotImplementedError('Provide the definition of validate algorithm')

    def _format_counter_block(self, iv: np.ndarray):
        raise NotImplementedError('Provide the definition of format counter block')

    def _perform_algorithm_specific_operation(self):
        raise NotImplementedError('Provide the definition of perform algorithm specific operation')

    def _get_associated_data_length(self) -> int:
        raise NotImplementedError('Provide the definition of get associated data length')

    def _encode_block(self):
        raise NotImplementedError('Provide the definition of encode block')

    def _final_block_special_handling(
            self,
            output_data: Union[str, np.ndarray],
            mac: Union[str, np.ndarray]
    ) -> Tuple[Union[str, np.ndarray], Union[str, np.ndarray]]:
        raise NotImplementedError('Provide the definition of final block special handling')

    def _set_key(self, key: Union[str, np.ndarray]):
        self.confidential.set_key(key)
        self.authentication.set_key(key)

    def _set_iv(self, iv: Union[str, np.ndarray]):
        # store iv
        self.iv = iv

        # format and store iv as numpy array
        _iv = Utility.copy_to_numpy(iv, error_msg='Invalid Initialization Vector')
        self._format_counter_block(_iv)

        # validate iv length
        if self._block_size != len(self.counter):
            raise ValueError(f'IV length {len(self.counter)} is not a valid block size')

        self.confidential.set_iv(self.counter)

    def generate_encrypt(
            self,
            input_data: Union[str, np.ndarray],
            output_data: np.ndarray = None,
            mac: np.ndarray = None,
            final: bool = False
    ) -> Union[str, np.ndarray]:
        # encrypt the input data for confidentiality
        output_data = self.confidential.encrypt(input_data, output_data, final)

        # encrypt the input data for authenticity
        if self.authenticate_output_data:
            _mac = self.authentication.generate(output_data, final, mac)
        else:
            _mac = self.authentication.generate(input_data, final, mac)

        if final:
            # GCM has special handling of last block : len(A) || len(C)
            output_data, _mac = self._final_block_special_handling(output_data, _mac)

            # perform final step
            if isinstance(_mac, str):
                _mac = Utility.copy_to_numpy(_mac)

            Bitwise.xor(_mac, self.cipher1, self.cipher1)
            mac_xor_cipher1 = self.cipher1[:self.t]

            # append MAC
            if isinstance(output_data, np.ndarray):
                result = np.zeros((len(output_data) + len(mac_xor_cipher1)), dtype=np.uint8)
                result[:len(output_data)] = output_data[:]
                result[len(output_data):] = mac_xor_cipher1[:]
                return result
            elif isinstance(output_data, str):
                return output_data + Utility.convert_to_str(mac_xor_cipher1)

        return output_data

    def decrypt_verify(
            self,
            input_data: Union[str, np.ndarray],
            mac: Union[str, np.ndarray] = None,
            output_data: np.ndarray = None,
            final: bool = False
    ) -> Union[str, np.ndarray]:
        if final:
            if mac is not None:
                _input_data = input_data
                _mac_to_verify = mac
            else:
                _input_data = Utility.copy_to_numpy(input_data)
                _mac_to_verify = _input_data[-self.t:]
                _input_data = _input_data[:-self.t]
        else:
            _input_data = input_data
            _mac_to_verify = None

        # decrypt the input data for confidentiality
        output_data = self.confidential.encrypt(_input_data, output_data, final)

        # encrypt the input data for authenticity
        _mac = self.authentication.generate(output_data, final)

        if final:
            # perform final step
            if isinstance(_mac, str):
                _mac = Utility.copy_to_numpy(_mac)
            Bitwise.xor(_mac, self.cipher1, self.cipher1)

            # verify MAC
            if np.any(_mac_to_verify != self.cipher1[:self.t]):
                raise ValueError("MAC is INVALID")

            if isinstance(input_data, str):
                return Utility.convert_to_str(output_data)

        return output_data
