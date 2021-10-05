import idc
import idautils
import idaapi

BUF_OFFSET = 16
BUFL_LEN_OFFSET = 24
MAX_PREV_CNT = 10

# String Decrypt Function
FUNC_NAME = "<Set String decrypt function name>"
decode_func = Appcall.proto(FUNC_NAME, "int __fastcall {:s}(char* buf, const char* enc);".format(FUNC_NAME))

ea = here()
func_addr = idc.get_name_ea_simple(FUNC_NAME)

for addr in idautils.CodeRefsTo(func_addr, 0):
    print("Addr 0x%08x" % addr)
    prev_ins = ida_search.find_code(addr, SEARCH_UP | SEARCH_NEXT)
    prev_ins_cnt = 1
    while prev_ins_cnt < MAX_PREV_CNT:
        prev_ins = ida_search.find_code(prev_ins, SEARCH_UP | SEARCH_NEXT)
        mnem = idc.print_insn_mnem(prev_ins)
        if mnem == 'lea':
            src_addr = idc.get_operand_value(prev_ins, 1)
            if idc.is_unknown(idc.get_full_flags(src_addr)) == True and idc.get_operand_type(prev_ins, 1) == o_mem:
                break
        prev_ins_cnt += 1
    if prev_ins_cnt == MAX_PREV_CNT:
        print("Not Found UNK blob")
        continue

    unk_data = src_addr
    print("Encrypted String Addr %08x" % unk_data)
    decoded_bytes = b''
    ida_dbg.refresh_debugger_memory()
    buf = Appcall.byref("\x00" * 256)
    ret = decode_func(buf, unk_data)
    buf_addr = idc.read_dbg_qword(ret + BUF_OFFSET)
    buf_len = (idc.read_dbg_qword(ret + BUFL_LEN_OFFSET)) * 2
    decoded_bytes = idc.get_strlit_contents(buf_addr, buf_len, STRTYPE_C_16)
    
    idc.set_cmt(unk_data, decoded_bytes.decode(), 1)
    print(decoded_bytes.decode())

ida_kernwin.jumpto(ea)