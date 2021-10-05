# DeObfuscate Opaque Predicate 

''' Pattern 
data:004A48C0 E8 54 39 02 00    call    loc_4C8219
data:004A48C5 4A 11 FB FF       dd 0FFFB114Ah
'''

import idaapi
import idautils
import idc

redirect_func_address = <jump function address> # e.g. 0x4C8219

def deobs_code_obfuscate(searchPattern, startAddress, endAddress):
    # Search
    pos = startAddress
    while pos < endAddress:
        pos = ida_search.find_binary(pos, endAddress , searchPattern, 0, SEARCH_DOWN)
        print("Position: 0x%x" % pos)
        if pos == idaapi.BADADDR:
            break

        func_addr = pos + 0x5 + idaapi.get_dword(pos + 1)
        func_addr = func_addr & 0xFFFFFFFF
        msg = "func_addr 0x{:08X}".format(func_addr)
        print(msg)

        if func_addr == redirect_func_address:
            addr = idaapi.get_dword(pos + 5)
            idaapi.patch_byte(pos, 0xE9)
            idaapi.patch_dword(pos + 1, addr)
            pos = pos + 9
        else:
            pos = pos + 1


def main():
    print("main start")
    start_ea = idc.get_segm_start(ida_kernwin.get_screen_ea())
    end_ea = idc.get_segm_end(start_ea)
    print("SEARCH START SEGMENT = 0x%x" % start_ea)
    print("SEARCH END SEMENT = 0x%x" % end_ea)
    OBFUS_PATTERN1 = "E8"
    print("call loc_xxxxx [%s]" % OBFUS_PATTERN1)
    deobs_code_obfuscate(OBFUS_PATTERN1, start_ea, end_ea)


if __name__ == '__main__':
    main()
    