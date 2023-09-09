# import external library
import numpy as np

# from import external library
from abc import ABC
from typing import Any, Tuple, Union


class Asymmetric(ABC):
    def __init__(self):
        # initialize key pair
        self.private_key = None
        self.public_key = None

    def set_key_pair(self, private_key: Any, public_key: Any):
        raise NotImplementedError('Provide the definition of set key pair method')

    def generate_key_pair(self) -> Tuple[Any, Any]:
        raise NotImplementedError('Provide the definition of generate key pair method')

    def validate_key_pair(self, private_key: Any, public_key: Any) -> bool:
        raise NotImplementedError('Provide the definition of validate key pair method')

    def distribute_key(self) -> Any:
        raise NotImplementedError('Provide the definition of distribute key method')

    def encrypt(self, input_data: Union[str, np.ndarray]) -> Union[str, np.ndarray]:
        raise NotImplementedError('Provide the definition of encrypt method')

    def decrypt(self, input_data: Union[str, np.ndarray]) -> Union[str, np.ndarray]:
        raise NotImplementedError('Provide the definition of decrypt method')


if __name__ == '__main__':
    try:
        Asymmetric().generate_key_pair()
    except NotImplementedError:
        print('Asymmetric interface cannot be instantiate')
