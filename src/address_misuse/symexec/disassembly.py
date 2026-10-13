"""This module contains the class used to represent disassembly code."""

from . import asm
from . import util


class Disassembly(object):
    """Disassembly class.

    Stores bytecode, and its disassembly.
    Additionally it will gather the following information on the existing functions in the disassembled code:
    - function hashes
    - function name to entry point mapping
    - function entry point to function name mapping
    """

    def __init__(self, code: str) -> None:
        """

        :param code:
        """
        self.bytecode = code
        if isinstance(code, str):
            self.instruction_list = asm.disassemble(util.safe_decode(code))
        else:
            self.instruction_list = asm.disassemble(code)

    def get_instruction_list(self) -> list:
        """"
        
        :return:
        """
        return self.instruction_list

    def get_easm(self):
        """

        :return:
        """
        return asm.instruction_list_to_easm(self.instruction_list)

