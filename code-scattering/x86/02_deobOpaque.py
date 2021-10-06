# Nop Out Opaque Predicate 

''' Pattern 
.data:0000000140060B5D 81 FC 70 49 00 00    cmp     rsp, 4970h
.data:0000000140060B64 E9 91 22 FC FF       jmp     loc_140022DFA
.data:0000000140022DFA 0F 82 EC FB FF FF    jb      sub_1400229EC
'''

import idaapi
import idautils
import idc
from idaemu import *

def deobs_opaque_predicate(searchPattern, startAddress, endAddress):

    emu_x86_ = Emu(UC_ARCH_X86, UC_MODE_32)
    emu_start = startAddress
    while emu_start < endAddress:
        emu_start = ida_search.find_binary(emu_start, endAddress , searchPattern, 0, SEARCH_DOWN)
        print("Emulation Start: 0x%x" % emu_start)
        if emu_start == idaapi.BADADDR:
            break
        print("[Debug] Dig into 0x%016X %s" % (emu_start, idc.generate_disasm_line(emu_start,0)))
        emu_x86_.eUntilAddress(emu_start, 0, Count=1)
        addr1 = emu_x86_.get_reg_value(UC_X86_REG_EIP)
        mnem_ret = idc.print_insn_mnem(addr1)
        opnd0_ret = idc.print_operand(addr1, 0)
        print("[Debug] Addr1 0x%016X %s" % (addr1, idc.generate_disasm_line(addr1,0)))
        emu_x86_.eUntilAddress(addr1, 0, Count=1)
        
        addr2 = emu_x86_.get_reg_value(UC_X86_REG_EIP)
        mnem_ret = idc.print_insn_mnem(addr2)
        opnd0_ret = idc.print_operand(addr2, 0)
        print("[Debug] Addr2 0x%016X %s" % (addr1, idc.generate_disasm_line(addr2,0)))
        if mnem_ret == 'jb': 
            print("Found Opaque Predicate!")
            for i in range(6):
                idc.patch_byte(emu_start + i, 0x90)
            # if jb short ..
            if idc.get_wide_byte(addr2) == 0x72:
                for i in range(2):
                    idc.patch_byte(addr2 + i, 0x90)
            else:
                for i in range(6):
                    idc.patch_byte(addr2 + i, 0x90)

        emu_start = idc.next_head(emu_start, idc.get_segm_end(startAddress)) # Find Next Match Pattern


def main():
    print("main start")
    start_ea = idc.get_segm_start(ida_kernwin.get_screen_ea())
    end_ea = idc.get_segm_end(start_ea)
    print("SEARCH START SEGMENT = 0x%x" % start_ea)
    print("SEARCH END SEMENT = 0x%x" % end_ea)
    OPAQUE_PATTERN1 = "81 FC ?? ?? 00 00 E9"
    print("Search cmp ... jmp  [%s]" % OPAQUE_PATTERN1)
    deobs_opaque_predicate(OPAQUE_PATTERN1, start_ea, end_ea)


if __name__ == '__main__':
    main()
    