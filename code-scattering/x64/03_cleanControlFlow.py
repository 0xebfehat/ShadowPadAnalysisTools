# Clean jmp control flow 

''' Pattern 
data:00459C1F E9 85 6D 01 00    jmp     loc_4709A9 <- rewrite jump to (target)
data:004709A9 90                nop
data:004709AA 90                nop
data:004709AB 90                nop
data:004709AC 90                nop
data:004709AD 90                nop
data:004709AE 90                nop
data:004709AF E9 F8 38 04 00    jmp     loc_4B42AC
[...]
data:0044DF1D 3B 44 24 28       cmp     eax, [esp+4+arg_20] (target)
'''

import idaapi
import idautils
import idc
from idaemu import *

MAX_EMU_CNT = 20


def clean_jmp_control_flow(searchPattern, startAddress, endAddress):

    emu_x86_ = Emu(UC_ARCH_X86, UC_MODE_64)
    emu_start = startAddress

    while emu_start < endAddress:
        target_address = idaapi.BADADDR
        emu_start = ida_search.find_binary(emu_start, endAddress , searchPattern, 0, SEARCH_DOWN)
        if emu_start == idaapi.BADADDR:
            break
        # Is code?
        if (idc.is_code(idc.get_full_flags(emu_start)) == True):
            emu_x86_.eUntilAddress(emu_start, 0, Count=1)
            rip = emu_x86_.get_reg_value(UC_X86_REG_RIP)
            mnem = idc.print_insn_mnem(rip)
            byte_code = idc.get_wide_byte(rip)
            if byte_code == 0x90:
                msg = "[Emulation Start] Found jmp xxxxx 0x%08X %s" % (emu_start, idc.generate_disasm_line(emu_start,0))
                print(msg)
                step_cnt = 0
                while step_cnt < MAX_EMU_CNT:
                    emu_x86_.eUntilAddress(rip, 0, Count=1)
                    disasm = idc.generate_disasm_line(rip,0)
                    mnem = idc.print_insn_mnem(rip)
                    byte_code = idc.get_wide_byte(rip) 
                    # NOP OUT
                    #if mnem == 'jmp':
                    if byte_code == 0xE9:
                        for i in range(5):
                            idc.patch_byte(rip + i, 0x90)
                    idc.auto_wait()
                    if (byte_code != 0x90) and (byte_code != 0xE9):
                        target_address = (rip - (emu_start + 5)) & 0xFFFFFFFF
                        msg = "new jmp target (Near Relative) 0x%08X (0x%08X)" % (target_address, rip)
                        print(msg)
                        idc.patch_dword(emu_start + 1, target_address)
                        idc.auto_wait()
                        break
                    rip = emu_x86_.get_reg_value(UC_X86_REG_RIP)
                if step_cnt == MAX_EMU_CNT:
                    print("Not Found Expcted Cotrol Flow")

        emu_start = emu_start + 5


def main():
    print("main start")
    start_ea = idc.get_segm_start(ida_kernwin.get_screen_ea())
    end_ea = idc.get_segm_end(start_ea)
    print("SEARCH START SEGMENT = 0x%x" % start_ea)
    print("SEARCH END SEMENT = 0x%x" % end_ea)
    # SEARCH jmp near relative 
    OPAQUE_PATTERN1 = "E9"
    print("Search jmp xxxxxx  [%s]" % OPAQUE_PATTERN1)
    clean_jmp_control_flow(OPAQUE_PATTERN1, start_ea, end_ea)


if __name__ == '__main__':
    main()
    