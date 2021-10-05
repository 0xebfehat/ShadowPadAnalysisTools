import idaapi
import idautils
import idc


# API Resovler Call Byte Pattern
API_CALL_BIN_PATTERN = "B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89"

# API Resolver Function
FUNC_NAME = "<Set API Resolver Funciton Name>"
api_resolv_func = Appcall.proto(FUNC_NAME, "int __fastcall {:s}(int id);".format(FUNC_NAME))

cur_pos = ida_kernwin.get_screen_ea()
seg_start = idc.get_segm_start(cur_pos)
seg_end = idc.get_segm_end(seg_start)
pos = seg_start 

while pos < seg_end:
    pos = ida_search.find_binary(pos, seg_end , API_CALL_BIN_PATTERN, 0, SEARCH_DOWN)
    if pos == idaapi.BADADDR:
        print("API Resolver Search Finished!")
        break
    print("API Resolver Call Address %08x" % pos)
    if idc.is_code(idc.get_full_flags(pos)) == False:
        idc.create_insn(pos)
    id = idc.get_operand_value(pos, 1)
    id = id & 0xFFFFFFFF
    api_addr = api_resolv_func(id)
    api_name = idc.get_name(api_addr, ida_name.GN_VISIBLE)
    next_ins = ida_search.find_code(pos, SEARCH_DOWN | SEARCH_NEXT)
    next_ins2 = ida_search.find_code(next_ins, SEARCH_DOWN | SEARCH_NEXT)
    api_addr_buf_data = idc.get_operand_value(next_ins2, 0)
    idc.set_name(api_addr_buf_data, api_name, ida_name.SN_CHECK | ida_name.SN_FORCE)
    print("API Resolved Name[%s] Address[%08x] Set Name[%08x]" % (api_name, api_addr, api_addr_buf_data))
    pos = next_ins2

ida_kernwin.jumpto(cur_pos)