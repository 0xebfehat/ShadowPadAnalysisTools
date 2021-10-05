import idc
import idautils
import idaapi

BUF_OFFSET = 8
MAX_PREV_CNT = 10

# API Resolver Function Definiton
FUNC_NAME = "<Set String decrypt function name>"
decode_func = Appcall.proto(FUNC_NAME, "int __usercall {:s}@<eax>(unsigned __int8 *a1@<eax>, _DWORD *a2@<ecx>);".format(FUNC_NAME))

ea = here()
func_addr = idc.get_name_ea_simple(FUNC_NAME)

for addr in idautils.CodeRefsTo(func_addr, 0):
    print("Address: 0x%08x" % addr)
    prev_ins = ida_search.find_code(addr, SEARCH_UP | SEARCH_NEXT)
    prev_ins_cnt = 1
    while prev_ins_cnt < MAX_PREV_CNT:
        prev_ins = ida_search.find_code(prev_ins, SEARCH_UP | SEARCH_NEXT)
        mnem = idc.print_insn_mnem(prev_ins)
        if mnem == 'mov':
            src_addr = idc.get_operand_value(prev_ins, 1)
            if idc.is_unknown(idc.get_full_flags(src_addr)) == True and idc.get_operand_type(prev_ins, 1) == o_imm:
                print("src_addr 0x%08x" % src_addr)
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
    ret = decode_func(unk_data, buf)
    buf_addr = idc.read_dbg_dword(ret + BUF_OFFSET)
    buf_len = -1
    decoded_bytes = idc.get_strlit_contents(buf_addr, buf_len, STRTYPE_C_16)
    
    idc.set_cmt(unk_data, decoded_bytes.decode(), 1)
    print("Decrypted String is \"%s\"" % decoded_bytes.decode())

ida_kernwin.jumpto(ea)