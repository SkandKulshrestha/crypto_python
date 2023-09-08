import numpy as np

from typing import Union


class Utility:
    @staticmethod
    def copy_to_numpy(data: Union[str, np.ndarray], out_data=None, error_msg: str = 'Invalid data'):
        if isinstance(data, str):
            _out_data = np.array(bytearray.fromhex(data))
        elif isinstance(data, np.ndarray):
            _out_data = np.copy(data)
        else:
            raise ValueError(f'{error_msg}. Only hex string and numpy array are supported')

        if out_data is None:
            out_data = _out_data
        else:
            out_data[:] = _out_data[:]

        return out_data

    @staticmethod
    def convert_to_str(data: np.ndarray) -> str:
        return bytes(data).hex().upper()
