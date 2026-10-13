# Vendored from Shao et al. (data/Address-Misuse/src/program_analyzer, Zenodo 17984167).
# Thay đổi so với bản gốc:
#   - import tương đối trong package address_misuse.symexec
#   - Timeout dùng SIGALRM (chỉ có trên Unix) được thay bằng kiểm tra deadline ở mỗi basic block,
#     chạy được trên Windows; z3 đã có timeout 1s mỗi lần check nên độ trễ dừng tối đa ~1s.
#   - process() nhận timeout_sec (mặc định 500s như paper).
import hashlib
import logging
import time
import traceback
import re
from collections import namedtuple
from .util import *
from .generator import Generator
from .disassembly import Disassembly
from .basic_block import BasicBlock

LOOP_LIMIT = 10
DEPTH_LIMIT = 100
DEFAULT_TIMEOUT_SEC = 500
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
Edge = namedtuple("Edge", ["v1", "v2"])


class Parameter:
    def __init__(self, **kwargs):
        attr_defaults = {
            "stack": [],
            "mem": {},
            "mem_real": [],
            "sha3_list": {},
            "global_state": {},
            "path_conditions_and_vars": {},
        }
        for attr, default in six.iteritems(attr_defaults):
            setattr(self, attr, kwargs.get(attr, default))

    def copy(self):
        _kwargs = custom_deepcopy(self.__dict__)
        return Parameter(**_kwargs)

class SymbolicExecutor:

    def __init__(self, addr: str, bytecode: str):
        self.addr = addr
        self.bytecode = bytecode
        self.disassembler = Disassembly(bytecode)
        self.gen = Generator()
        self.solver = Solver()
        self.solver.set("timeout", 1000)
        self.blocks = []
        self.vertices = {} # block vertice to block

        self.depth = 0
        self.visited_edges = {}

        self.detection_res = {
            "addr": self.addr, 
            "time": None, 
            "delegatecall": {
                "valid": False,
                "instances": []
            },
            "transfer_all_eth": {
                "valid": False
            },
            "transfer_msg_value": {
                "valid": False
            },
            "transfer_input_amount": {
                "valid": False
            }, 
            "self_destruct": {
                "valid": False
            }, 
            "transfer_token": {
                "push_0xa9059cbb": False
            }
        }


    def get_init_params(self) -> Parameter:

        sender_address = BitVec("Is", 256)
        receiver_address = BitVec("Ia", 256)
        deposited_value = BitVec("Iv", 256)
        init_is = BitVec("init_Is", 256)
        init_ia = BitVec("init_Ia", 256)

        global_state = {
            "sender_address" : sender_address,
            "receiver_address": receiver_address,
            "value": deposited_value,
            "gasprice": BitVec("gasprice", 256),
            "origin": BitVec("origin", 256),
            "coinbase": BitVec("coinbase", 256),
            "timestamp": BitVec("timestamp", 256),
            "number": BitVec("number", 256),
            "difficulty": BitVec("difficulty", 256),
            "gaslimit": BitVec("gaslimit", 256),
            "chainid": BitVec("chainid", 256),
            "basefee": BitVec("basefee", 256),

            "balance": {},
            "pc": 0
        }

        path_conditions_and_vars = {
            "path_condition": [],
            "Is": sender_address,
            "Ia": receiver_address,
            "Iv": deposited_value
        }

        constraint = deposited_value >= BitVecVal(0, 256)
        path_conditions_and_vars["path_condition"].append(constraint)
        constraint = init_is >= deposited_value
        path_conditions_and_vars["path_condition"].append(constraint)
        constraint = init_ia >= BitVecVal(0, 256)
        path_conditions_and_vars["path_condition"].append(constraint)

        global_state["balance"]["Is"] = init_is - deposited_value
        global_state["balance"]["Ia"] = init_ia + deposited_value
        global_state["balance"][str(mask_address_var(sender_address))] = init_is - deposited_value
        global_state["balance"][str(mask_address_var(receiver_address))] = init_ia + deposited_value

        if "Ia" not in global_state:
            global_state["Ia"] = {}

        params = Parameter(
            path_conditions_and_vars=path_conditions_and_vars,
            global_state=global_state,
        )

        return params


    def process(self, timeout_sec: float = DEFAULT_TIMEOUT_SEC):
        self.deadline = time.monotonic() + timeout_sec
        self.timed_out = False
        try:
            instruction_list = self.disassembler.get_instruction_list()
            self.construct_bb(instruction_list, self.blocks)
            params = self.get_init_params()
            self.sym_exec_block(params, 0, 0)
            log.debug("Done Symbolic execution")
        except TimeoutError:
            self.timed_out = True
            log.info("Time over! Done Symbolic execution")
            return
    

    
    def load_size_mem_info(self, mem_real, start, end):
        res = []
        for info in mem_real:
            if info["start"] >= start and info["end"] <= end:
                res.append(info)
        return res

    def load_mem_info(self, mem_real, start, end):
        for info in mem_real:
            if start == info["start"] and end == info["end"]:
                return True,info
        return False,{}
    
    def add_mem_info(self, meminfo, mem_real):    
        new_mem_real = []
        for info in mem_real:
            if info["end"] < meminfo["start"] or info["start"] > meminfo["end"]:
                new_mem_real.append(info)
            # elif info["start"] < meminfo["start"]:
            #     gap = meminfo["start"] - info["start"]
        new_mem_real.append(meminfo)
        mem_real.clear()
        for info in new_mem_real:
            mem_real.append(info)

    
    def construct_bb(self, instruction_list: list[dict], blocks: list[BasicBlock]):
        current_block = BasicBlock(0)
        for i, instruction in enumerate(instruction_list):
            address = instruction.get("address")
            opcode = instruction.get("opcode")
            argument = instruction.get("argument")
            if argument:
                full_opcode = opcode + " " + argument
            else:
                full_opcode = opcode
            current_block.add_instruction(full_opcode)

            if opcode in ["JUMP", "JUMPI", "STOP", "RETURN", "REVERT", "INVALID", "SELFDESTRUCT"]:
                if opcode == "JUMPI":
                    current_block.set_falls_to(address + 1)
                current_block.set_block_end(address)
                blocks.append(current_block)
                current_block = BasicBlock(address + 1)
            elif i < len(instruction_list) - 1 and instruction_list[i + 1]["opcode"] == "JUMPDEST":
                next_instruction_address = instruction_list[i + 1]["address"]
                current_block.set_falls_to(next_instruction_address)
                current_block.set_block_end(address)
                blocks.append(current_block)
                current_block = BasicBlock(next_instruction_address)
        
        last_instruction_address = instruction_list[len(instruction_list) - 1]["address"]
        if not current_block.is_empty():
            current_block.set_block_end(last_instruction_address)
            blocks.append(current_block)

        for i, block in enumerate(blocks):
            end_address = block.get_end_address()
            for instruction in instruction_list:
                if instruction["address"] == end_address:
                    end_opcode = instruction["opcode"]
                    break

            if (end_opcode == "JUMPI"):
                block.set_block_type("conditional")
            elif (end_opcode == "JUMP"):
                block.set_block_type("unconditional")
            elif (end_opcode == "STOP" or end_opcode == "RETURN" or end_opcode == "SELFDESTRUCT" or end_opcode == "REVERT" or end_opcode == "INVALID"):
                block.set_block_type("terminal")
            elif end_address == last_instruction_address:
                block.set_block_type("terminal")
            else:
                block.set_block_type("falls_to")

        for i, block in enumerate(blocks):
            vertice = block.get_start_address()
            self.vertices[vertice] = block


    def sym_exec_block(self, params: Parameter, block_vertice: int, pre_block_vertice: int):
        if time.monotonic() > self.deadline:
            raise TimeoutError("symbolic execution deadline exceeded")

        self.depth += 1
        if self.depth > DEPTH_LIMIT:
            self.depth -= 1
            return 

        current_edge = Edge(pre_block_vertice, block_vertice)
        if current_edge in self.visited_edges:
            updated_count_number = self.visited_edges[current_edge] + 1
            self.visited_edges.update({current_edge: updated_count_number})
        else:
            self.visited_edges.update({current_edge: 1})

        if self.visited_edges[current_edge] > LOOP_LIMIT:
            self.depth -= 1
            updated_count_number = self.visited_edges[current_edge] - 1
            self.visited_edges.update({current_edge: updated_count_number})
            return 


        block: BasicBlock = self.vertices[block_vertice]
        block_instructions = block.get_instructions()

        for i, instr in enumerate(block_instructions):
            self.sym_exec_ins(params, block_vertice, instr)

        if block.get_block_type() == "terminal":
            pass
        elif block.get_block_type() == "unconditional":
            successor = block.get_jump_target()
            params.global_state["pc"] = successor
            self.sym_exec_block(params, block_vertice=successor, pre_block_vertice=block_vertice)
        elif block.get_block_type() == "falls_to":
            successor = block.get_falls_to()
            params.global_state["pc"] = successor
            self.sym_exec_block(params, block_vertice=successor, pre_block_vertice=block_vertice)
        elif block.get_block_type() == "conditional":
            branch_expression = block.get_branch_expression()
            self.solver.push() 
            self.solver.add(branch_expression)

            try:
                ret = self.solver.check()
                if ret == unsat:
                    log.debug("INFEASIBLE PATH DETECTED")
                else:
                    left_branch = block.get_jump_target()

                    new_params = params.copy()
                    new_params.global_state["pc"] = left_branch
                    new_params.path_conditions_and_vars["path_condition"].append(branch_expression)
                       
                    self.sym_exec_block(new_params, block_vertice=left_branch, pre_block_vertice=block_vertice)
            except TimeoutError:
                raise
            except Exception as e:
                traceback.print_exc()
            
            self.solver.pop()
            self.solver.push()  
            negated_branch_expression = Not(branch_expression)
            self.solver.add(negated_branch_expression)

            try:
                ret = self.solver.check()
                if ret == unsat:
                    log.debug("INFEASIBLE PATH DETECTED")
                else:
                    right_branch = block.get_falls_to()
                    new_params = params.copy()
                    new_params.global_state["pc"] = right_branch
                    new_params.path_conditions_and_vars["path_condition"].append(negated_branch_expression)
                    self.sym_exec_block(new_params, block_vertice=right_branch, pre_block_vertice=block_vertice)
            except TimeoutError:
                raise
            except Exception as e:
                traceback.print_exc()
            
            self.solver.pop()
        
        self.depth -= 1
        updated_count_number = self.visited_edges[current_edge] - 1
        self.visited_edges.update({current_edge: updated_count_number})
        return


    def sym_exec_ins(self, params: Parameter, block_vertice: int, instr: str):

        stack = params.stack
        mem = params.mem
        mem_real = params.mem_real
        global_state = params.global_state
        sha3_list = params.sha3_list
        path_conditions_and_vars = params.path_conditions_and_vars
        
        instr_parts = instr.split(" ")
        opcode = instr_parts[0]

        if opcode == "INVALID":
            global_state["pc"] = global_state["pc"] + 1
            return
        elif opcode == "ASSERTFAIL":
            global_state["pc"] = global_state["pc"] + 1
            return

        log.debug("==============================")
        log.debug("EXECUTING: " + instr)

        #
        #  0s: Stop and Arithmetic Operations
        #
        if opcode == "STOP":
            global_state["pc"] = global_state["pc"] + 1
            return
        elif opcode == "ADD":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                # Type conversion is needed when they are mismatched
                if isReal(first) and isSymbolic(second):
                    first = BitVecVal(first, 256)
                    computed = first + second
                elif isSymbolic(first) and isReal(second):
                    second = BitVecVal(second, 256)
                    computed = first + second
                else:
                    # both are real and we need to manually modulus with 2 ** 256
                    # if both are symbolic z3 takes care of modulus automatically
                    computed = (first + second) % (2**256)
                computed = simplify(computed) if is_expr(computed) else computed
                stack.insert(0, computed)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "MUL":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                if isReal(first) and isSymbolic(second):
                    first = BitVecVal(first, 256)
                elif isSymbolic(first) and isReal(second):
                    second = BitVecVal(second, 256)
                computed = first * second & UNSIGNED_BOUND_NUMBER
                computed = simplify(computed) if is_expr(computed) else computed
                stack.insert(0, computed)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "SUB":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                if isReal(first) and isSymbolic(second):
                    first = BitVecVal(first, 256)
                    computed = first - second
                elif isSymbolic(first) and isReal(second):
                    second = BitVecVal(second, 256)
                    computed = first - second
                else:
                    computed = (first - second) % (2**256)
                computed = simplify(computed) if is_expr(computed) else computed
                stack.insert(0, computed)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "DIV":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                if isAllReal(first, second):
                    if second == 0:
                        computed = 0
                    else:
                        first = to_unsigned(first)
                        second = to_unsigned(second)
                        computed = first // second
                else:
                    first = to_symbolic(first)
                    second = to_symbolic(second)
                    # The program will check itself, no need to check here
                    computed = UDiv(first, second)
                computed = simplify(computed) if is_expr(computed) else computed
                stack.insert(0, computed)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "SDIV":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                if isAllReal(first, second):
                    first = to_signed(first)
                    second = to_signed(second)
                    if second == 0:
                        computed = 0
                    elif first == -(2**255) and second == -1:
                        computed = -(2**255)
                    else:
                        sign = -1 if (first / second) < 0 else 1
                        computed = sign * (abs(first) / abs(second))
                else:
                    first = to_symbolic(first)
                    second = to_symbolic(second)

                    computed = first / second
                computed = simplify(computed) if is_expr(computed) else computed
                stack.insert(0, computed)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "MOD":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                if isAllReal(first, second):
                    if second == 0:
                        computed = 0
                    else:
                        first = to_unsigned(first)
                        second = to_unsigned(second)
                        computed = first % second & UNSIGNED_BOUND_NUMBER

                else:
                    first = to_symbolic(first)
                    second = to_symbolic(second)
                    computed = URem(first, second)

                computed = simplify(computed) if is_expr(computed) else computed
                stack.insert(0, computed)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "SMOD":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                if isAllReal(first, second):
                    if second == 0:
                        computed = 0
                    else:
                        first = to_signed(first)
                        second = to_signed(second)
                        sign = -1 if first < 0 else 1
                        computed = sign * (abs(first) % abs(second))
                else:
                    first = to_symbolic(first)
                    second = to_symbolic(second)

                    self.solver.push()
                    self.solver.add(Not(second == 0))
                    if check_sat(self.solver) == unsat:
                        # it is provable that second is indeed equal to zero
                        computed = 0
                    else:
                        self.solver.push()
                        self.solver.add(first < 0)  # check sign of first element
                        sign = (
                            BitVecVal(-1, 256)
                            if check_sat(self.solver) == sat
                            else BitVecVal(1, 256)
                        )
                        self.solver.pop()

                        def z3_abs(x):
                            return If(x >= 0, x, -x)

                        first = z3_abs(first)
                        second = z3_abs(second)

                        computed = sign * (first % second)
                    self.solver.pop()

                computed = simplify(computed) if is_expr(computed) else computed
                stack.insert(0, computed)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "ADDMOD":
            if len(stack) > 2:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                third = stack.pop(0)

                if isAllReal(first, second, third):
                    if third == 0:
                        computed = 0
                    else:
                        computed = (first + second) % third
                else:
                    first = to_symbolic(first)
                    second = to_symbolic(second)
                    self.solver.push()
                    self.solver.add(Not(third == 0))
                    if check_sat(self.solver) == unsat:
                        computed = 0
                    else:
                        first = ZeroExt(256, first)
                        second = ZeroExt(256, second)
                        third = ZeroExt(256, third)
                        computed = (first + second) % third
                        computed = Extract(255, 0, computed)
                    self.solver.pop()
                computed = simplify(computed) if is_expr(computed) else computed
                stack.insert(0, computed)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "MULMOD":
            if len(stack) > 2:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                third = stack.pop(0)

                if isAllReal(first, second, third):
                    if third == 0:
                        computed = 0
                    else:
                        computed = (first * second) % third
                else:
                    first = to_symbolic(first)
                    second = to_symbolic(second)
                    self.solver.push()
                    self.solver.add(Not(third == 0))
                    if check_sat(self.solver) == unsat:
                        computed = 0
                    else:
                        first = ZeroExt(256, first)
                        second = ZeroExt(256, second)
                        third = ZeroExt(256, third)
                        computed = URem(first * second, third)
                        computed = Extract(255, 0, computed)
                    self.solver.pop()
                computed = simplify(computed) if is_expr(computed) else computed
                stack.insert(0, computed)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "EXP":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                base = stack.pop(0)
                exponent = stack.pop(0)
                # Type conversion is needed when they are mismatched
                if isAllReal(base, exponent):
                    computed = pow(base, exponent, 2**256)
                else:
                    # The computed value is unknown, this is because power is
                    # not supported in bit-vector theory
                    new_var_name = self.gen.gen_arbitrary_var()
                    computed = BitVec(new_var_name, 256)
                computed = simplify(computed) if is_expr(computed) else computed
                stack.insert(0, computed)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "SIGNEXTEND":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                if isAllReal(first, second):
                    if first >= 32 or first < 0:
                        computed = second
                    else:
                        signbit_index_from_right = 8 * first + 7
                        if second & (1 << signbit_index_from_right):
                            computed = second | (2**256 - (1 << signbit_index_from_right))
                        else:
                            computed = second & ((1 << signbit_index_from_right) - 1)
                else:
                    first = to_symbolic(first)
                    second = to_symbolic(second)
                    self.solver.push()
                    self.solver.add(Not(Or(first >= 32, first < 0)))
                    if check_sat(self.solver) == unsat:
                        computed = second
                    else:
                        signbit_index_from_right = 8 * first + 7
                        self.solver.push()
                        self.solver.add(second & (1 << signbit_index_from_right) == 0)
                        if check_sat(self.solver) == unsat:
                            computed = second | (2**256 - (1 << signbit_index_from_right))
                        else:
                            computed = second & ((1 << signbit_index_from_right) - 1)
                        self.solver.pop()
                    self.solver.pop()
                computed = simplify(computed) if is_expr(computed) else computed
                stack.insert(0, computed)
            else:
                raise ValueError("STACK underflow")
        #
        #  10s: Comparison and Bitwise Logic Operations
        #
        elif opcode == "LT":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)

                if isAllReal(first, second):
                    first = to_unsigned(first)
                    second = to_unsigned(second)
                    if first < second:
                        computed = 1
                    else:
                        computed = 0
                else:
                    computed = If(ULT(first, second), BitVecVal(1, 256), BitVecVal(0, 256))
                computed = simplify(computed) if is_expr(computed) else computed
                stack.insert(0, computed)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "GT":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)

                if isAllReal(first, second):
                    first = to_unsigned(first)
                    second = to_unsigned(second)
                    if first > second:
                        computed = 1
                    else:
                        computed = 0
                else:
                    computed = If(UGT(first, second), BitVecVal(1, 256), BitVecVal(0, 256))
                computed = simplify(computed) if is_expr(computed) else computed
                stack.insert(0, computed)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "SLT":  # Not fully faithful to signed comparison
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                if isAllReal(first, second):
                    first = to_signed(first)
                    second = to_signed(second)
                    if first < second:
                        computed = 1
                    else:
                        computed = 0
                else:
                    computed = If(first < second, BitVecVal(1, 256), BitVecVal(0, 256))
                computed = simplify(computed) if is_expr(computed) else computed
                stack.insert(0, computed)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "SGT":  # Not fully faithful to signed comparison
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                if isAllReal(first, second):
                    first = to_signed(first)
                    second = to_signed(second)
                    if first > second:
                        computed = 1
                    else:
                        computed = 0
                else:
                    computed = If(first > second, BitVecVal(1, 256), BitVecVal(0, 256))
                computed = simplify(computed) if is_expr(computed) else computed
                stack.insert(0, computed)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "EQ":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                if isAllReal(first, second):
                    if first == second:
                        computed = 1
                    else:
                        computed = 0
                else:
                    computed = If(first == second, BitVecVal(1, 256), BitVecVal(0, 256))
                computed = simplify(computed) if is_expr(computed) else computed
                stack.insert(0, computed)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "ISZERO":
            # Tricky: this instruction works on both boolean and integer,
            # when we have a symbolic expression, type error might occur
            # Currently handled by try and catch
            if len(stack) > 0:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                if isReal(first):
                    if first == 0:
                        computed = 1
                    else:
                        computed = 0
                else:
                    computed = If(first == 0, BitVecVal(1, 256), BitVecVal(0, 256))
                computed = simplify(computed) if is_expr(computed) else computed
                stack.insert(0, computed)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "AND":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                computed = first & second
                computed = simplify(computed) if is_expr(computed) else computed
                stack.insert(0, computed)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "OR":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                computed = first | second
                computed = simplify(computed) if is_expr(computed) else computed
                stack.insert(0, computed)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "XOR":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                second = stack.pop(0)
                computed = first ^ second
                computed = simplify(computed) if is_expr(computed) else computed
                stack.insert(0, computed)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "NOT":
            if len(stack) > 0:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                computed = (~first) & UNSIGNED_BOUND_NUMBER
                computed = simplify(computed) if is_expr(computed) else computed
                stack.insert(0, computed)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "BYTE":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                first = stack.pop(0)
                byte_index = 32 - first - 1
                second = stack.pop(0)

                if isAllReal(first, second):
                    if first >= 32 or first < 0:
                        computed = 0
                    else:
                        computed = second & (255 << (8 * byte_index))
                        computed = computed >> (8 * byte_index)
                else:
                    first = to_symbolic(first)
                    second = to_symbolic(second)
                    self.solver.push()
                    self.solver.add(Not(Or(first >= 32, first < 0)))
                    if check_sat(self.solver) == unsat:
                        computed = 0
                    else:
                        computed = second & (255 << (8 * byte_index))
                        computed = computed >> (8 * byte_index)
                    self.solver.pop()
                computed = simplify(computed) if is_expr(computed) else computed
                stack.insert(0, computed)
            else:
                raise ValueError("STACK underflow")
        #
        # 20s: SHA3/KECCAK256
        #
        elif opcode in ["KECCAK256", "SHA3"]:
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1

                offset = stack.pop(0)
                size = stack.pop(0)
                if isAllReal(offset, size):
                    valueList = self.load_size_mem_info(mem_real, offset, offset + size - 1)
                    if len(valueList) > 0:
                        sorted_valueList = sorted(valueList, key=lambda x: (x["start"]))
                        sorted_values = [item["value"] for item in sorted_valueList]
                        data = [str(x) for x in sorted_values]
                        position = "".join(data)
                        position = hashlib.md5(position.encode()).hexdigest()

                        if position in sha3_list:
                            stack.insert(0, sha3_list[position])
                        else:
                            sha3_var_name = self.gen.gen_sha3_var()
                            sha3_var = BitVec(sha3_var_name, 256)
                            sha3_list[position] = sha3_var
                            stack.insert(0, sha3_var)
                    else:
                        new_sha3_var_name = self.gen.gen_sha3_var()
                        new_sha3_var = BitVec(new_sha3_var_name, 256)
                        path_conditions_and_vars[new_sha3_var_name] = new_sha3_var
                        stack.insert(0, new_sha3_var)
                else:
                    new_sha3_var_name = self.gen.gen_sha3_var()
                    new_sha3_var = BitVec(new_sha3_var_name, 256)
                    path_conditions_and_vars[new_sha3_var_name] = new_sha3_var
                    stack.insert(0, new_sha3_var)
            else:
                raise ValueError("STACK underflow")
        #
        # 30s: Environment Information
        #
        elif opcode == "ADDRESS":  # get address of currently executing account
            global_state["pc"] = global_state["pc"] + 1
            stack.insert(0, global_state["receiver_address"])
        elif opcode == "BALANCE":
            if len(stack) > 0:
                global_state["pc"] = global_state["pc"] + 1
                address = stack.pop(0)
                if isReal(address):
                    hashed_address = "concrete_address_" + str(address)
                else:
                    hashed_address = str(address)

                if hashed_address in global_state["balance"]:
                    balance = global_state["balance"][hashed_address]
                else:
                    new_var_name = self.gen.gen_balance_var(hashed_address)
                    if new_var_name in path_conditions_and_vars:
                        new_var = path_conditions_and_vars[new_var_name]
                    else:
                        new_var = BitVec(new_var_name, 256)
                        path_conditions_and_vars[new_var_name] = new_var
                    global_state["balance"][hashed_address] = new_var
                    balance = new_var

                stack.insert(0, balance)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "CALLER":  # get caller address
            # that is directly responsible for this execution
            global_state["pc"] = global_state["pc"] + 1
            stack.insert(0, global_state["sender_address"])
        elif opcode == "ORIGIN":  # get execution origination address
            global_state["pc"] = global_state["pc"] + 1
            stack.insert(0, global_state["origin"])
        elif opcode == "CALLVALUE":  # get value of this transaction
            global_state["pc"] = global_state["pc"] + 1
            stack.insert(0, global_state["value"])
            # buy function feature: msg.value to transfer the token

        elif opcode == "CALLDATALOAD":  # from inputter data from environment
            if len(stack) > 0:
                global_state["pc"] = global_state["pc"] + 1
                position = stack.pop(0)
                new_var_name = self.gen.gen_calldataload_var(position)
                if new_var_name in path_conditions_and_vars:
                    new_var = path_conditions_and_vars[new_var_name]
                else:
                    new_var = BitVec(new_var_name, 256)
                    path_conditions_and_vars[new_var_name] = new_var
                stack.insert(0, new_var)

                # if new_var not in path_conditions_and_vars["input"]:
                #     path_conditions_and_vars["input"].append(new_var)

            else:
                raise ValueError("STACK underflow")
        elif opcode == "CALLDATASIZE":
            global_state["pc"] = global_state["pc"] + 1
            calldata_size_var_name = self.gen.gen_calldata_size()
            if calldata_size_var_name in path_conditions_and_vars:
                calldata_size_var = path_conditions_and_vars[calldata_size_var_name]
            else:
                calldata_size_var = BitVec(calldata_size_var_name, 256)
                path_conditions_and_vars[calldata_size_var_name] = calldata_size_var
            stack.insert(0, calldata_size_var)
        elif opcode == "CALLDATACOPY":  # Copy inputter data to memory
            #  TODO: Don't know how to simulate this yet
            if len(stack) > 2:
                global_state["pc"] = global_state["pc"] + 1
                stack.pop(0)
                stack.pop(0)
                stack.pop(0)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "CODESIZE":
            global_state["pc"] = global_state["pc"] + 1
            evm = self.bytecode
            code_size = len(evm) / 2
            stack.insert(0, code_size)
        elif opcode == "CODECOPY":
            if len(stack) > 2:
                global_state["pc"] = global_state["pc"] + 1
                mem_location = stack.pop(0)
                code_from = stack.pop(0)
                no_bytes = stack.pop(0)
                
                if isAllReal(code_from, no_bytes):
                    evm = self.bytecode
                    start = code_from * 2
                    end = start + no_bytes * 2
                    code = evm[start:end]
                    code_var = int(code, 16)
                else:
                    code_var_name = self.gen.gen_code_var("Ia", code_from, no_bytes)
                    if code_var_name in path_conditions_and_vars:
                        code_var = path_conditions_and_vars[code_var_name]
                    else:
                        code_var = BitVec(code_var_name, 256)
                        path_conditions_and_vars[code_var_name] = code_var

                if isAllReal(mem_location, no_bytes):
                    meminfo = {
                        "start": mem_location,
                        "end": mem_location + no_bytes - 1,
                        "value": code_var
                    }
                    self.add_mem_info(meminfo, mem_real)
                else:
                    mem[str(mem_location)] = code_var
            else:
                raise ValueError("STACK underflow")
        elif opcode == "RETURNDATACOPY":
            if len(stack) > 2:
                global_state["pc"] += 1
                stack.pop(0)
                stack.pop(0)
                stack.pop(0)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "RETURNDATASIZE":
            global_state["pc"] += 1
            new_var_name = self.gen.gen_returndatasize_var()
            # new_var_name = self.gen.gen_arbitrary_var()
            new_var = BitVec(new_var_name, 256)
            stack.insert(0, new_var)
        elif opcode == "GASPRICE":
            global_state["pc"] = global_state["pc"] + 1
            stack.insert(0, global_state["gasprice"])
        elif opcode == "EXTCODESIZE":
            if len(stack) > 0:
                global_state["pc"] = global_state["pc"] + 1
                address = stack.pop(0)

                # not handled yet
                new_var_name = self.gen.gen_code_size_var(address)
                if new_var_name in path_conditions_and_vars:
                    new_var = path_conditions_and_vars[new_var_name]
                else:
                    new_var = BitVec(new_var_name, 256)
                    path_conditions_and_vars[new_var_name] = new_var
                stack.insert(0, new_var)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "EXTCODECOPY":
            if len(stack) > 3:
                global_state["pc"] = global_state["pc"] + 1
                address = stack.pop(0)
                mem_location = stack.pop(0)
                code_from = stack.pop(0)
                no_bytes = stack.pop(0)

                code_var_name = self.gen.gen_code_var(address, code_from, no_bytes)
                if code_var_name in path_conditions_and_vars:
                    code_var = path_conditions_and_vars[code_var_name]
                else:
                    code_var = BitVec(code_var_name, 256)
                    path_conditions_and_vars[code_var_name] = code_var

                if isAllReal(mem_location, no_bytes):
                    meminfo = {
                        "start": mem_location,
                        "end": mem_location + no_bytes - 1,
                        "value": code_var
                    }
                    self.add_mem_info(meminfo, mem_real)
                else:
                    mem[str(mem_location)] = code_var

            else:
                raise ValueError("STACK underflow")

        elif opcode == "EXTCODEHASH":
            if len(stack) > 1:
                address = stack.pop(0)

                if(str(address) in sha3_list):
                    stack.insert(0, sha3_list[str(address)])
                else:
                    sha3_var_name = self.gen.gen_sha3_var()
                    sha3_var = BitVec(sha3_var_name, 256)
                    sha3_list[str(address)] = sha3_var
                    stack.insert(0, sha3_var)
            else:
                raise ValueError("STACK underflow")

        #
        #  40s: Block Information
        #
        elif opcode == "BLOCKHASH":  # information from block header
            if len(stack) > 0:
                global_state["pc"] = global_state["pc"] + 1
                blocknumber = stack.pop(0)
                new_var_name = self.gen.gen_blockhash_var(blocknumber)
                if new_var_name in path_conditions_and_vars:
                    new_var = path_conditions_and_vars[new_var_name]
                else:
                    new_var = BitVec(new_var_name, 256)
                    path_conditions_and_vars[new_var_name] = new_var
                stack.insert(0, new_var)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "COINBASE":  # information from block header
            global_state["pc"] = global_state["pc"] + 1
            stack.insert(0, global_state["coinbase"])
        elif opcode == "TIMESTAMP":  # information from block header
            global_state["pc"] = global_state["pc"] + 1
            stack.insert(0, global_state["timestamp"])
        elif opcode == "NUMBER":  # information from block header
            global_state["pc"] = global_state["pc"] + 1
            stack.insert(0, global_state["number"])
        elif opcode == "DIFFICULTY":  # information from block header
            global_state["pc"] = global_state["pc"] + 1
            stack.insert(0, global_state["difficulty"])
        elif opcode == "GASLIMIT":  # information from block header
            global_state["pc"] = global_state["pc"] + 1
            stack.insert(0, global_state["gaslimit"])
        #
        #  50s: Stack, Memory, Storage, and Flow Information
        #
        elif opcode == "POP":
            if len(stack) > 0:
                global_state["pc"] = global_state["pc"] + 1
                stack.pop(0)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "MLOAD":
            if len(stack) > 0:
                global_state["pc"] = global_state["pc"] + 1
                stored_address = stack.pop(0)
                if isReal(stored_address):
                    flag, info = self.load_mem_info(mem_real, stored_address, stored_address + 31)
                    if not flag:
                        var_name =  self.gen.gen_mem_var(stored_address)
                        new_var = BitVec(var_name, 256)
                        stack.insert(0, new_var)

                        meminfo = {
                            "start": stored_address,
                            "end": stored_address + 31,
                            "value": new_var
                        }
                        self.add_mem_info(meminfo, mem_real)

                    else:
                        stack.insert(0, info["value"])
                else:
                    if str(stored_address) not in mem:
                        var_name =  self.gen.gen_mem_var(stored_address)
                        new_var = BitVec(var_name, 256)
                        mem[str(stored_address)] = new_var
                    stack.insert(0, mem[str(stored_address)])
                
            else:
                raise ValueError("STACK underflow")
        elif opcode == "MSTORE":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                stored_address = stack.pop(0)
                stored_value = stack.pop(0)
                # MSTORE slotid to MEM32

                if isReal(stored_address):
                    # mem[stored_address] = stored_value
                    meminfo = {
                        "start": stored_address, 
                        "end": stored_address + 31, 
                        "value": stored_value
                    }
                    self.add_mem_info(meminfo, mem_real)
                else:
                    mem[str(stored_address)] = stored_value
            else:
                raise ValueError("STACK underflow")
        elif opcode == "MSTORE8":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                stored_address = stack.pop(0)
                temp_value = stack.pop(0)
                stored_value = temp_value % 256  # get the least byte

                if isReal(stored_address):
                    # mem[stored_address] = stored_value
                    meminfo = {
                        "start": stored_address,
                        "end": stored_address,
                        "value": stored_value
                    }
                    self.add_mem_info(meminfo, mem_real)
                else:
                    mem[str(stored_address)] = stored_value
            else:
                raise ValueError("STACK underflow")
        elif opcode == "SLOAD":
            if len(stack) > 0:
                global_state["pc"] = global_state["pc"] + 1
                position = stack.pop(0)

                if isReal(position) and position in global_state["Ia"]:
                    value = global_state["Ia"][position]
                    stack.insert(0, value)
                else:
                    if str(position) in global_state["Ia"]:
                        value = global_state["Ia"][str(position)]
                        stack.insert(0, value)
                    else:
                        if is_expr(position):
                            position = simplify(position)

                        new_var_name = self.gen.gen_store_var(position)
                        # ?Prev Edition to get param name

                        if new_var_name in path_conditions_and_vars:
                            new_var = path_conditions_and_vars[new_var_name]
                        else:
                            new_var = BitVec(new_var_name, 256)
                            path_conditions_and_vars[new_var_name] = new_var
                        stack.insert(0, new_var)
                        if isReal(position):
                            global_state["Ia"][position] = new_var
                        else:
                            global_state["Ia"][str(position)] = new_var
            else:
                raise ValueError("STACK underflow")

        elif opcode == "SSTORE":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                stored_address = stack.pop(0)
                stored_value = stack.pop(0)

                if isReal(stored_address):
                    # note that the stored_value could be unknown
                    global_state["Ia"][stored_address] = stored_value
                else:
                    # note that the stored_value could be unknown
                    global_state["Ia"][str(stored_address)] = stored_value
            else:
                raise ValueError("STACK underflow")
        elif opcode == "JUMP":
            if len(stack) > 0:
                target_address = stack.pop(0)
                if isSymbolic(target_address):
                    try:
                        target_address = int(str(simplify(target_address)))
                    except:
                        raise TypeError("Target address must be an integer")
                self.vertices[block_vertice].set_jump_target(target_address)
                # if target_address not in edges[block]:
                #     edges[block].append(target_address)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "JUMPI":
            # We need to prepare two branches
            if len(stack) > 1:
                target_address = stack.pop(0)

                if isSymbolic(target_address):
                    try:
                        target_address = int(str(simplify(target_address)))
                    except:
                        raise TypeError("Target address must be an integer")
                self.vertices[block_vertice].set_jump_target(target_address)
                flag = stack.pop(0)
                branch_expression = BitVecVal(0, 1) == BitVecVal(1, 1)
                if isReal(flag):
                    if flag != 0:
                        branch_expression = True
                else:
                    branch_expression = flag != 0
                self.vertices[block_vertice].set_branch_expression(branch_expression)
                # if target_address not in edges[block]:
                #     edges[block].append(target_address)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "PC":
            stack.insert(0, global_state["pc"])
            global_state["pc"] = global_state["pc"] + 1
        elif opcode == "MSIZE":
            global_state["pc"] = global_state["pc"] + 1
            new_msize_var_name = self.gen.gen_msize_var()
            new_msize_var = BitVec(new_msize_var_name, 256)
            path_conditions_and_vars[new_msize_var_name] = new_msize_var
            stack.insert(0, new_msize_var)
        elif opcode == "GAS":
            # In general, we do not have this precisely. It depends on both
            # the initial gas and the amount has been depleted
            # we need o think about this in the future, in case precise gas
            # can be tracked
            global_state["pc"] = global_state["pc"] + 1
            new_var_name = self.gen.gen_gas_var()
            new_var = BitVec(new_var_name, 256)
            path_conditions_and_vars[new_var_name] = new_var
            stack.insert(0, new_var)
        elif opcode == "JUMPDEST":
            # Literally do nothing
            global_state["pc"] = global_state["pc"] + 1

        elif opcode == "TLOAD":
            if len(stack) > 0:
                global_state["pc"] = global_state["pc"] + 1
                stack.pop(0)
                new_var_name = self.gen.gen_transient_storage_var()
                new_var = BitVec(new_var_name, 256)
                stack.insert(0, new_var)
                pass
            else:
                raise ValueError("STACK underflow")
        elif opcode == "TSTORE":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                stack.pop(0)
                stack.pop(0)
                pass
            else:
                raise ValueError("STACK underflow")
        elif opcode == "MCOPY":
            if len(stack) > 2:
                global_state["pc"] = global_state["pc"] + 1
                stack.pop(0)
                stack.pop(0)
                stack.pop(0)
                pass
            else:
                raise ValueError("STACK underflow")
        #
        #  60s & 70s: Push Operations
        #
        elif opcode.startswith("PUSH", 0):  # this is a push instruction
            position = int(opcode[4:], 10)
            global_state["pc"] = global_state["pc"] + 1 + position
            if position == 0:
                pushed_value = 0
            else:
                pushed_value = int(instr_parts[1], 16)
            stack.insert(0, pushed_value)

            if instr == "PUSH4 0xa9059cbb":
                pass
        #
        #  80s: Duplication Operations
        #
        elif opcode.startswith("DUP", 0):
            global_state["pc"] = global_state["pc"] + 1
            position = int(opcode[3:], 10) - 1
            if len(stack) > position:
                duplicate = stack[position]
                stack.insert(0, duplicate)
            else:
                raise ValueError("STACK underflow")

        #
        #  90s: Swap Operations
        #
        elif opcode.startswith("SWAP", 0):
            global_state["pc"] = global_state["pc"] + 1
            position = int(opcode[4:], 10)
            if len(stack) > position:
                temp = stack[position]
                stack[position] = stack[0]
                stack[0] = temp
            else:
                raise ValueError("STACK underflow")

        #
        #  a0s: Logging Operations
        #
        elif opcode in ("LOG0", "LOG1", "LOG2", "LOG3", "LOG4"):
            global_state["pc"] = global_state["pc"] + 1
            # We do not simulate these log operations
            num_of_pops = 2 + int(opcode[3:])
            if len(stack) >= num_of_pops:
                while num_of_pops > 0:
                    stack.pop(0)
                    num_of_pops -= 1
            else:
                raise ValueError("STACK underflow")
        #
        #  f0s: System Operations
        #
        elif opcode  == "CREATE":
            if len(stack) > 2:
                global_state["pc"] += 1
                stack.pop(0)
                stack.pop(0)
                stack.pop(0)
                new_var_name = self.gen.gen_arbitrary_var()
                new_var = BitVec(new_var_name, 256)
                stack.insert(0, new_var)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "CREATE2":
            if len(stack) > 3:
                global_state["pc"] += 1
                stack.pop(0)
                stack.pop(0)
                stack.pop(0)
                stack.pop(0)
                new_var_name = self.gen.gen_arbitrary_var()
                new_var = BitVec(new_var_name, 256)
                stack.insert(0, new_var)
            else:
                raise ValueError("STACK underflow")
        elif opcode == "CALL":
            # TODO: Need to handle miu_i
            if len(stack) > 6:
                global_state["pc"] = global_state["pc"] + 1
                outgas = stack.pop(0)
                recipient = stack.pop(0)
                transfer_amount = stack.pop(0)
                start_data_input = stack.pop(0)
                size_data_input = stack.pop(0)
                start_data_output = stack.pop(0)
                size_data_ouput = stack.pop(0)

                self.extract_call_info(transfer_amount, global_state, path_conditions_and_vars)
                # in the paper, it is shaky when the size of data output is
                # min of stack[6] and the | o |

                return_data_var_name = self.gen.gen_return_data()
                if return_data_var_name in path_conditions_and_vars:
                    return_data_var = path_conditions_and_vars[return_data_var_name]
                else:
                    return_data_var = BitVec(return_data_var_name, 256)
                    path_conditions_and_vars[return_data_var_name] = return_data_var
                
                if isReal(transfer_amount):
                    if transfer_amount == 0:
                        stack.insert(0, 1)  # x = 0

                        if isReal(size_data_ouput):
                            if size_data_ouput == 0:
                                pass
                            else:
                                if isReal(start_data_output):
                                    meminfo = {
                                        "start": start_data_output,
                                        "end": start_data_output + size_data_ouput - 1,
                                        "value": return_data_var
                                    }
                                    self.add_mem_info(meminfo, mem_real)
                                    
                                elif isSymbolic(start_data_output):
                                    for i in range(size_data_ouput):
                                        index = simplify(start_data_output + i)
                                        if str(index) in mem:
                                            mem.pop(str(index))
                                    mem[str(start_data_output)] = return_data_var
                        
                        return

                # Let us ignore the call depth
                balance_ia = global_state["balance"]["Ia"]
                is_enough_fund = transfer_amount <= balance_ia

                # the execution is possibly okay
                stack.insert(0, 1)  # x = 1

                if isReal(size_data_ouput):
                    if size_data_ouput == 0:
                        pass
                    else:
                        if isReal(start_data_output):
                            meminfo = {
                                "start": start_data_output,
                                "end": start_data_output + size_data_ouput - 1,
                                "value": return_data_var
                            }
                            self.add_mem_info(meminfo, mem_real)
                            
                        elif isSymbolic(start_data_output):
                            for i in range(size_data_ouput):
                                index = simplify(start_data_output + i)
                                if str(index) in mem:
                                    mem.pop(str(index))
                            mem[str(start_data_output)] = return_data_var

                    self.solver.add(is_enough_fund)
                    path_conditions_and_vars["path_condition"].append(is_enough_fund)

                    new_balance_ia = balance_ia - transfer_amount
                    global_state["balance"]["Ia"] = new_balance_ia
                    address_is = path_conditions_and_vars["Is"]

                    address_is = simplify(address_is & CONSTANT_ONES_159)
                    if (address_is == recipient):
                        new_balance_is = global_state["balance"]["Is"] + transfer_amount
                        global_state["balance"]["Is"] = new_balance_is
                    else:
                        if isReal(recipient):
                            new_address_name = "concrete_address_" + str(recipient)
                        else:
                            new_address_name = str(recipient)

                        if new_address_name in global_state["balance"]:
                            old_balance = global_state["balance"][new_address_name]
                        else:
                            old_balance_name = self.gen.gen_balance_var(new_address_name)
                            
                            if old_balance_name in path_conditions_and_vars:
                                old_balance = path_conditions_and_vars[old_balance_name]
                            else:
                                old_balance = BitVec(old_balance_name, 256)
                                path_conditions_and_vars[old_balance_name] = old_balance

                        constraint = old_balance >= 0
                        self.solver.add(constraint)
                        path_conditions_and_vars["path_condition"].append(constraint)
                        new_balance = old_balance + transfer_amount
                        global_state["balance"][new_address_name] = new_balance
            else:
                raise ValueError("STACK underflow")
        elif opcode == "CALLCODE":
            # TODO: Need to handle miu_i
            if len(stack) > 6:
                global_state["pc"] = global_state["pc"] + 1
                outgas = stack.pop(0)
                recipient = stack.pop(0)  # this is not used as recipient

                transfer_amount = stack.pop(0)
                start_data_input = stack.pop(0)
                size_data_input = stack.pop(0)
                start_data_output = stack.pop(0)
                size_data_ouput = stack.pop(0)
                # in the paper, it is shaky when the size of data output is
                # min of stack[6] and the | o |

                if isReal(transfer_amount):
                    if transfer_amount == 0:
                        stack.insert(0, 1)  # x = 0
                        return

                # Let us ignore the call depth
                balance_ia = global_state["balance"]["Ia"]
                is_enough_fund = transfer_amount <= balance_ia

                # the execution is possibly okay
                stack.insert(0, 1)  # x = 1
                self.solver.add(is_enough_fund)
                path_conditions_and_vars["path_condition"].append(is_enough_fund)
            else:
                raise ValueError("STACK underflow")
        
        
        elif opcode == "DELEGATECALL":
            if len(stack) > 5:
                global_state["pc"] += 1
                stack.pop(0)
                recipient = stack.pop(0)
                stack.pop(0)
                stack.pop(0)
                stack.pop(0)
                stack.pop(0)

                self.extract_delegatecall_addr(str(recipient))
                new_var_name = self.gen.gen_DSCALL_res_var()
                new_var = BitVec(new_var_name, 256)
                stack.insert(0, new_var)
            else:
                raise ValueError("STACK underflow")
        
        elif opcode == "STATICCALL":
            if len(stack) > 5:
                global_state["pc"] += 1
                stack.pop(0)
                recipient = stack.pop(0)
                stack.pop(0)
                stack.pop(0)
                stack.pop(0)
                stack.pop(0)
                new_var_name = self.gen.gen_DSCALL_res_var()
                new_var = BitVec(new_var_name, 256)
                stack.insert(0, new_var)
            else:
                raise ValueError("STACK underflow")
        elif opcode in ("RETURN", "REVERT"):
            # TODO: Need to handle miu_i
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                stack.pop(0)
                stack.pop(0)
                # TODO
                pass
            else:
                raise ValueError("STACK underflow")
        elif opcode == "SELFDESTRUCT":
            global_state["pc"] = global_state["pc"] + 1
            recipient = stack.pop(0)
            transfer_amount = global_state["balance"]["Ia"]
            global_state["balance"]["Ia"] = 0

            if isReal(recipient):
                hashed_address = "concrete_address_" + str(recipient)
            else:
                hashed_address = str(recipient)

            if hashed_address in global_state["balance"]:
                old_balance = global_state["balance"][hashed_address]
            else:
                old_balance_name = self.gen.gen_balance_var(hashed_address)
                
                if old_balance_name in path_conditions_and_vars:
                    old_balance = path_conditions_and_vars[old_balance_name]
                else:
                    old_balance = BitVec(old_balance_name, 256)
                    path_conditions_and_vars[old_balance_name] = old_balance

            constraint = old_balance >= 0
            # self.solver.add(constraint)
            path_conditions_and_vars["path_condition"].append(constraint)
            new_balance = old_balance + transfer_amount
            global_state["balance"][hashed_address] = new_balance
            # TODO

            self.extract_SELFDESTRUCT(transfer_amount)
            return

        # brand new opcodes
        elif opcode == "SHL":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                shift = stack.pop(0)
                value = stack.pop(0)
                if isReal(value):
                    value = BitVecVal(value, 256)
                computed = value << shift

                computed = simplify(computed) if is_expr(computed) else computed
                stack.insert(0, computed)
            else:
                raise ValueError("STACK underflow")

        elif opcode == "SHR":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                # *Simpler model
                shift = stack.pop(0)
                value = stack.pop(0)
                # Type conversion is needed when they are mismatched
                if isReal(value):
                    value = BitVecVal(value, 256)
                computed = LShR(value, shift)

                computed = simplify(computed) if is_expr(computed) else computed
                stack.insert(0, computed)
            else:
                raise ValueError("STACK underflow")

        elif opcode == "SAR":
            if len(stack) > 1:
                global_state["pc"] = global_state["pc"] + 1
                # *Simpler model
                shift = stack.pop(0)
                value = stack.pop(0)
                # Type conversion is needed when they are mismatched
                if isReal(value):
                    value = BitVecVal(value, 256)
                computed = value >> shift

                computed = simplify(computed) if is_expr(computed) else computed
                stack.insert(0, computed)
            else:
                raise ValueError("STACK underflow")

        elif opcode == "SELFBALANCE":
            # address(this).balance
            global_state["pc"] = global_state["pc"] + 1
            stack.insert(0, global_state["balance"]["Ia"])

        elif opcode == "CHAINID":
            # chain_id = {  1 // mainnet
            #    {  2 // Morden testnet (disused)
            #    {  2 // Expanse mainnet
            #    {  3 // Ropsten testnet
            #    {  4 // Rinkeby testnet
            #    {  5 // Goerli testnet
            #    { 42 // Kovan testnet
            #    { ...
            global_state["pc"] = global_state["pc"] + 1
            stack.insert(0, global_state["chainid"])

        elif opcode == "BASEFEE":
            global_state["pc"] = global_state["pc"] + 1
            stack.insert(0, global_state["basefee"])

        else:
            log.info("UNKNOWN INSTRUCTION: " + opcode)
            raise Exception("UNKNOWN INSTRUCTION: " + opcode)


    def extract_delegatecall_addr(self, masked_delegatecall_addr: str):
        self.detection_res["delegatecall"]["valid"] = True
        # 'Concat(0,\n       Extract(159,\n               0,\n               Ia-store_24440054405305269366569402256811496959409073762505157381672968839269610695612))'

        # print("masked_delegatecall_addr:", masked_delegatecall_addr)
        if masked_delegatecall_addr.isdigit():
            logic_addr = hex(int(masked_delegatecall_addr))
            # print("logic_addr", logic_addr)
            self.detection_res["delegatecall"]["instances"].append({
                "type": "hardcoded",
                "logic_addr": logic_addr
            })
            return 

        matches = re.findall(r"\b(?:Ia-store|calldata)_\d+\b", masked_delegatecall_addr)
        if len(matches) > 0:
            delegatecall_addr = matches[0]
            addr_source = delegatecall_addr.split("_")[0]
            if addr_source == "Ia-store":
                delegatecall_type = "sload"
                sload_position = delegatecall_addr.split("_")[1]
                sload_position_hex_str = hex(int(sload_position))
                delegatecall_sload = sload_position_hex_str
                self.detection_res["delegatecall"]["instances"].append({
                    "type": delegatecall_type,
                    "slot": delegatecall_sload
                })
            elif addr_source == "calldata":
                self.detection_res["delegatecall"]["instances"].append({
                    "type": "calldata"
                })
        
    def extract_call_info(self, value, global_state, path_conditions_and_vars):
        if value == global_state["balance"]["Ia"]:
            self.detection_res["transfer_all_eth"]["valid"] = True
        if value == path_conditions_and_vars["Iv"]:
            self.detection_res["transfer_msg_value"]["valid"] = True

        if re.match(r'^calldata_\d+$', str(value)):
        # if str(value).startswith("calldata_"):
            self.detection_res["transfer_input_amount"]["valid"] = True

    def extract_SELFDESTRUCT(self, value):
        self.detection_res["self_destruct"]["valid"] = True