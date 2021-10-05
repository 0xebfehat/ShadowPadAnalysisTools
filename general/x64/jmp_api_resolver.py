import idaapi
import idautils
import idc


BINARY_SEARCH_PATTERN = '48 B8' # mov rax, xxxxxxxxxxxxxxxx
DLL_NAME_LIST = ['ws2_32_']


def main():

    start_segm = idc.get_segm_start(here())
    end_segm = idc.get_segm_end(here())
    print("Start Segment [0x%08X]" % start_segm)
    print("End Segment [0x%08X]" % end_segm)

    pos = start_segm

    while pos < end_segm:
        pos = ida_search.find_binary(pos, end_segm , BINARY_SEARCH_PATTERN, 0, SEARCH_DOWN)
        if pos > end_segm:
            break

        if (idc.is_data(idc.get_full_flags(pos)) == True):
            print("Skip Data 0x%08X" % pos)
            continue

        if (idc.is_code(idc.get_full_flags(pos)) == False):
            idc.create_insn(pos)
            idc.auto_wait()
            print("MakeCode! 0x%08X" % pos)

        mnem = idc.print_insn_mnem(pos)
        opnd0 = idc.print_operand(pos, 0)
        if (mnem == 'mov' and opnd0 == 'rax'):
            func_start = pos
            pos = idc.next_head(pos)
            mnem = idc.print_insn_mnem(pos)
            opnd0 = idc.print_operand(pos, 0)
            if (mnem == 'neg' and opnd0 == 'rax'):
                pos = idc.next_head(pos)
                mnem = idc.print_insn_mnem(pos)
                opnd0 = idc.print_operand(pos, 0)
                if (mnem == 'jmp' and opnd0 == 'rax'): # Found Pattern!
                    opnd1 = idc.get_operand_value(func_start, 1)
                    api_addr = (~opnd1 & 0xFFFFFFFFFFFFFFFF) + 1
                    api_name = idc.get_name(api_addr)
                    name_flag = False
                    print("api_name: %s" % api_name)
                    for dll_name in DLL_NAME_LIST:
                        if api_name.find(dll_name) == 0:
                            api_name = api_name.replace(dll_name, '')
                            name_flag = True
                            break
                    if name_flag == True:
                        api_name2 = 'j_' + api_name
                    else:
                        if not api_name == '':
                            api_name2 = api_name.split('_')
                            api_name2 = 'j_' + api_name2[1]
                    ida_funcs.add_func(func_start)
                    idc.auto_wait()
                    idaapi.set_name(func_start, api_name2, idaapi.SN_FORCE)
                    idc.auto_wait()
                    print("[0x%08X] API : %s Jumper Address: 0x%08X" % (api_addr, api_name, func_start))
                else:
                    ida_bytes.del_items(func_start)
            else:
                ida_bytes.del_items(func_start)
        else:
            ida_bytes.del_items(pos)

if __name__ == '__main__':
    main()

