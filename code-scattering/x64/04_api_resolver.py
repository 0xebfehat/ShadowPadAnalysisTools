import idaapi
import idautils
import idc
import ida_dbg

MAX_STEP_CNT = 20

def resolve_api(searchPattern, startAddress, endAddress, maxStepCnt):
    dbg_start = startAddress
    while dbg_start < endAddress:
        dbg_start = ida_search.find_binary(dbg_start, endAddress , searchPattern, 0, SEARCH_DOWN)
        print("Debug Start: 0x%08X" % dbg_start)
        if dbg_start == idaapi.BADADDR:
            break
        idc.set_reg_value(dbg_start, 'RIP')
        step_cnt = 1 
        while step_cnt <= maxStepCnt:
            ida_dbg.step_into()
            ida_dbg.wait_for_next_event(WFNE_SUSP, -1)
            rip_val = ida_dbg.get_ip_val()
            mnem = idc.print_insn_mnem(rip_val)
            if (mnem == 'call'): 
                ida_dbg.step_over()
                ida_dbg.wait_for_next_event(WFNE_SUSP, -1)
                rax_value = idc.get_reg_value('RAX')
                api_name = idc.get_name(rax_value, ida_name.GN_VISIBLE)
                print("0x%016X Resolved API:%s Address: 0x%08X" % (dbg_start, api_name, rax_value))
                target = (dbg_start + 6) + idc.get_wide_dword(dbg_start + 2)
                idc.set_name(target, api_name, ida_name.SN_CHECK | ida_name.SN_FORCE)
                break
            step_cnt = step_cnt + 1
        dbg_start = idc.next_head(dbg_start, endAddress) 

def main():
    print("main start")
    start_ea = idc.get_segm_start(ida_kernwin.get_screen_ea())
    end_ea = idc.get_segm_end(start_ea)
    print("SEARCH START SEGMENT = 0x%x" % start_ea)
    print("SEARCH END SEGMENT = 0x%x" % end_ea)
    START_PATTERN = "FF 15 ?? ?? ?? ?? E9"
    resolve_api(START_PATTERN, start_ea, end_ea, MAX_STEP_CNT)

if __name__ == '__main__':
    main()


