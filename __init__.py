from binaryninja import (
        BinaryView,
        SegmentFlag,

        Architecture,
        RegisterInfo,
        InstructionInfo,

        BranchType,
        
        InstructionTextToken,
        InstructionTextTokenType,

        LowLevelILOperation, LowLevelILLabel,

        FlagRole,
        LowLevelILFlagCondition,

        CallingConvention,

        log_error
)
import traceback

from arch import *
from util import *

ops = { 'ad', 'adc', 'adci', 'adcim', 'adcm', 'adf', 'adfm', 'adi', 'adim', 'adm', 'an', 'ani', 'anm',
        'b', 'bf', 'bfm', 'br', 'bra', 'brr', 'c', 'caa', 'caar', 'cm', 'cmf', 'cmfm', 'cmi', 'cmim', 'cmm', 'cr',
        'dbrk', 'di', 'dmt', 'dv', 'dvf', 'dvfm', 'dvi', 'dvim', 'dvis', 'dvism', 'dvm', 'dvs', 'dvsm',
        'ei', 'fti', 'ftim', 'ht', 'ir', 'itf', 'itfm', 'lds', 'ldt', 'ldw', 'md', 'mdf', 'mdfm', 'mdi', 'mdim',
        'mdis', 'mdism', 'mdm', 'mds', 'mdsm', 'mh', 'ml', 'ms', 'mu', 'muf', 'mufm', 'mui', 'muim', 'muis',
        'muism', 'mum', 'mus', 'musm', 'ng', 'ngf', 'ngfm', 'ngm', 'nt', 'ntm', 'or', 'ori', 'orm',
        're', 'rf', 'rl', 'rli', 'rlim', 'rlm', 'rmp', 'rnd', 'rndm', 'rr', 'rri', 'rrim', 'rrm', 'sa', 'sai',
        'saim', 'sam', 'sb', 'sbc', 'sbci', 'sbcim', 'sbcm', 'sbf', 'sbfm', 'sbi', 'sbim', 'sbm', 'ses', 'sew',
        'sf', 'sl', 'sli', 'slim', 'slm', 'smp', 'sr', 'sri', 'srim', 'srm', 'sts', 'stt', 'stw', 'wt',
        'xr', 'xri', 'xrm', 'zes', 'zew' }


class BitReader16(BitReader):
    def _ensure_bits(self, nbits):
        while self._cs < nbits:
            self._c <<= 9
            l = self._r.read_byte()
            r = self._r.read_byte()
            #nyte = (l << 1) | (r >> 7)
            nyte = (l << 8) | r
            self._c |= nyte
            self._cs += 9


class Clemency(Architecture):
    name = "clemency"
    address_size = 4
    default_int_size = 4

    # Register setup
    regs = {
            'R0' : RegisterInfo('R0', 4),
            'R1' : RegisterInfo('R1', 4),
            'R2' : RegisterInfo('R2', 4),
            'R3' : RegisterInfo('R3', 4),
            'R4' : RegisterInfo('R4', 4),
            'R5' : RegisterInfo('R5', 4),
            'R6' : RegisterInfo('R6', 4),
            'R7' : RegisterInfo('R7', 4),
            'R8' : RegisterInfo('R8', 4),
            'R9' : RegisterInfo('R9', 4),
            'R10' : RegisterInfo('R10', 4),
            'R11' : RegisterInfo('R11', 4),
            'R12' : RegisterInfo('R12', 4),
            'R13' : RegisterInfo('R13', 4),
            'R14' : RegisterInfo('R14', 4),
            'R15' : RegisterInfo('R15', 4),
            'R16' : RegisterInfo('R16', 4),
            'R17' : RegisterInfo('R17', 4),
            'R18' : RegisterInfo('R18', 4),
            'R19' : RegisterInfo('R19', 4),
            'R20' : RegisterInfo('R20', 4),
            'R21' : RegisterInfo('R21', 4),
            'R22' : RegisterInfo('R22', 4),
            'R23' : RegisterInfo('R23', 4),
            'R24' : RegisterInfo('R24', 4),
            'R25' : RegisterInfo('R25', 4),
            'R26' : RegisterInfo('R26', 4),
            'R27' : RegisterInfo('R27', 4),
            'R28' : RegisterInfo('R28', 4),
            'ST'  : RegisterInfo('ST', 4),
            'RA'  : RegisterInfo('RA', 4),
            'PC'  : RegisterInfo('PC', 4)
    }

    stack_pointer = 'ST'


    # Flag setup
    flags = ['s', 'o', 'c', 'z']

    flag_roles = {
        's' : FlagRole.NegativeSignFlagRole,
        'o' : FlagRole.OverflowFlagRole,
        'c' : FlagRole.CarryFlagRole,
        'z' : FlagRole.ZeroFlagRole
    }

    flag_write_types = ['', '*']

    flags_written_by_flag_write_type = {
        '*': ['s', 'o', 'c', 'z']
    }


    flags_required_for_flag_condition = {
        LowLevelILFlagCondition.LLFC_NE: ['z'],   #not equal
        LowLevelILFlagCondition.LLFC_E: ['z'],    #equal
        
        LowLevelILFlagCondition.LLFC_ULT: ['c', 'z'], # unsigned less than
        LowLevelILFlagCondition.LLFC_ULE: ['c', 'z'], # unsigned less than or equal
        LowLevelILFlagCondition.LLFC_UGT: ['c', 'z'], # unsigned greater than
        LowLevelILFlagCondition.LLFC_UGE: ['c', 'z'], # unsigned greater than or equal
        
        LowLevelILFlagCondition.LLFC_SLT: ['s'], # signed less than
        LowLevelILFlagCondition.LLFC_SLE: ['s', 'z'], # signed less than or equal
        LowLevelILFlagCondition.LLFC_SGT: ['s', 'z'], # signed greater than
        LowLevelILFlagCondition.LLFC_SGE: ['s'], # signed greater than or equal
        
        LowLevelILFlagCondition.LLFC_NEG: ['s'], # negative
        LowLevelILFlagCondition.LLFC_POS: ['s'], # positive
        
        LowLevelILFlagCondition.LLFC_O: ['o'],   # overflow
        LowLevelILFlagCondition.LLFC_NO: ['o']   # no overflow
    }


    def perform_get_instruction_info(self, data, addr):

        reader = BitReader16(BytestringReader(data))
        try:
            ins = disassemble(reader)
        except InvalidMachineCodeException as e:
            log_error("InvalidMachineCodeException at address: " + hex(addr) + " {0}".format(e))
            return None

        insInfo = InstructionInfo()
        insInfo.length = reader.nytes_read() * 2

        op = ins.mnemonic
        if op in ['re', 'ht']:
            insInfo.add_branch(BranchType.FunctionReturn)
        elif op in ['b', 'brr']:
            # relative direct unconditional
            insInfo.add_branch(BranchType.UnconditionalBranch, addr + 2 * ins.op1.value)
        elif op in ['bn', 'be', 'bl', 'ble', 'bg', 'bge', 'bno', 'bo', 'bns', 'bs', 'bsl', 'bsle', 'bsg', 'bsge']:
            # relative direct conditional
            insInfo.add_branch(BranchType.TrueBranch, addr + 2 * ins.op1.value)
            insInfo.add_branch(BranchType.FalseBranch, addr + insInfo.length)
        elif op == 'br':
            # absolute indirect unconditonal
            insInfo.add_branch(BranchType.IndirectBranch)
        elif op in ['brn', 'bre', 'brl', 'brle', 'brg', 'brge', 'brno', 'bro', 'brns', 'brs', 'brsl', 'brsle', 'brsg', 'brsge']:
            # absolute indirect conditonal
            insInfo.add_branch(BranchType.TrueBranch)
            insInfo.add_branch(BranchType.FalseBranch, addr + insInfo.length)
        elif op == 'bra':
            # absolute direct
            insInfo.add_branch(BranchType.UnconditionalBranch, 2 * ins.op1.value)
        elif op in ['c', 'car']:
            # relative direct unconditional
            insInfo.add_branch(BranchType.CallDestination, addr + 2 * ins.op1.value)
        elif op in ['cn', 'ce', 'cl', 'cle', 'cg', 'cge', 'cno', 'co', 'cns', 'cs', 'csl', 'csle', 'csg', 'csge']:
            # relative direct conditional
            insInfo.add_branch(BranchType.CallDestination, addr + 2 * ins.op1.value)
            #insInfo.add_branch(BranchType.TrueBranch, addr + 2 * ins.op1.value)
            insInfo.add_branch(BranchType.FalseBranch, addr + insInfo.length)
        elif op == 'caa':
            insInfo.add_branch(BranchType.CallDestination, 2 * ins.op1.value)
        elif op == 'cr':
            insInfo.add_branch(BranchType.CallDestination)
        elif op in ['crn', 'cre', 'crl', 'crle', 'crg', 'crge', 'crno', 'cro', 'crns', 'crs', 'crsl', 'crsle', 'crsg', 'crsge']:
            insInfo.add_branch(BranchType.CallDestination)
            insInfo.add_branch(BranchType.FalseBranch, addr + insInfo.length)

        return insInfo


    
    def perform_get_instruction_text(self, data, addr):
        reader = BitReader16(BytestringReader(data))
        try:
            ins = disassemble(reader)
        except InvalidMachineCodeException:
            log_error("InvalidMachineCodeException at address: " + addr)
            return None

        tokens = []

        tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, ins.mnemonic))
        tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "))

       
        if ins.is_load_or_store():
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, str(ins.op1.reg)))
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', ['))
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, str(ins.op2.reg)))
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ' + '))
            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken,
                hex(2 * ins.op3.value), 2 * ins.op3.value))
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '))
            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, str(ins.op4.value), ins.op4.value))
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ']'))
        elif ins.is_direct_relative_jmp_or_call():
            tokens.append(InstructionTextToken(InstructionTextTokenType.CodeRelativeAddressToken,
                hex(addr + 2 * ins.op1.value), addr + 2 * ins.op1.value))
        elif ins.is_direct_jmp_or_call():
            tokens.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken,
                            hex(2 * ins.op1.value), 2 * ins.op1.value))
        elif ins.mnemonic == 'mov':
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, str(ins.op1.reg)))
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '))
            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken,
                hex(ins.op2.value), ins.op2.value))
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ' / '))
            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken,
                hex(2 * ins.op2.value), 2 * ins.op2.value))
        else: 
            for i, op in enumerate(ins.operands):
                if op.is_reg():
                    tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, str(op.reg)))
                elif op.is_imm():
                    tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken,
                        hex(op.value), op.value))
                if i + 1 != ins.arity:
                    tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', '))

        global strings
        if ins.mnemonic == 'mov' and ins.operands[1].value in strings:
            string = strings[ins.operands[1].value]
            tokens.append(InstructionTextToken(InstructionTextTokenType.StringToken, ' // {}'.format(string)))
        return tokens, reader.nytes_read() * 2



    def perform_get_instruction_low_level_il(self, data, addr, il):

        reader = BitReader16(BytestringReader(data))
        try:
            ins = disassemble(reader)
        except InvalidMachineCodeException:
            log_error("InvalidMachineCodeException at address: " + addr)
            return None

        # TODO

        return reader.nytes_read() * 2

strings = {}

class ClemencyView(BinaryView):
    name = "clemency"
    long_name = "cLEMENCy executable"

    def __init__(self, data):
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)
        self.raw = data
        if data.file.filename.endswith('.bin.16'):
            orig_file = data.file.filename[:-3]
            global strings
            strings = find_strings(orig_file)

    @classmethod
    def is_valid_for_data(self, data):
        return True

    def init(self):
        try:
            self.platform = Architecture['clemency'].standalone_platform
            self.arch = Architecture['clemency']

            self.add_entry_point(0x0)

            self.add_auto_segment(0x0000000, 2 * 0x3FFFFFF, 0x0, len(self.raw),
                    SegmentFlag.SegmentExecutable | SegmentFlag.SegmentReadable)

        except:
            log_error(traceback.format_exc())
            return False

        return True

ClemencyView.register()
Clemency.register()
