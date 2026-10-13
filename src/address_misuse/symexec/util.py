import six
from z3 import *

CONSTANT_ONES_159 = BitVecVal((1 << 160) - 1, 256)
UNSIGNED_BOUND_NUMBER = 2**256 - 1


def safe_decode(hex_encoded_string):
    """

    :param hex_encoded_string:
    :return:
    """
    if hex_encoded_string.startswith("0x"):
        return bytes.fromhex(hex_encoded_string[2:])
    else:
        return bytes.fromhex(hex_encoded_string)
    
def isSymbolic(value):
    return not isinstance(value, six.integer_types)

def isReal(value):
    return isinstance(value, six.integer_types)

def isAllReal(*args):
    for element in args:
        if isSymbolic(element):
            return False
    return True

def to_symbolic(number):
    if isReal(number):
        return BitVecVal(number, 256)
    return number

def to_unsigned(number):
    if number < 0:
        return number + 2**256
    return number

def to_signed(number):
    if number > 2 ** (256 - 1):
        return (2 ** (256) - number) * (-1)
    else:
        return number

def check_sat(solver, pop_if_exception=True):
    try:
        ret = solver.check()
        if ret == unknown:
            # raise Z3Exception(solver.reason_unknown())
            pass
    except Exception as e:
        if pop_if_exception:
            solver.pop()
        raise e
    return ret

def mask_address_var(var):
    if not isinstance(var, str) and isSymbolic(var):
        var = var & CONSTANT_ONES_159
        var = simplify(var) if is_expr(var) else var
    return var

def custom_deepcopy(input):
    output = {}
    for key in input:
        if isinstance(input[key], list):
            output[key] = list(input[key])
        elif isinstance(input[key], dict):
            output[key] = custom_deepcopy(input[key])
        else:
            output[key] = input[key]
    return output