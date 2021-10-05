import idc
import idautils
import idaapi
import re

BUF_OFFSET = 8
MAX = 100
ALPHA_NUM_CHAR = re.compile(r'^[a-zA-Z0-9 !-/:-@¥[-`{-~\n|\r\n|\r]*$')

# decrypt string function 
FUNC_NAME = "<Set String decrypt function name>" # e.g. sub_*****
decode_func = Appcall.proto(FUNC_NAME, "int __usercall {:s}@<eax>(unsigned __int8 *a1@<eax>, _DWORD *a2@<ecx>);".format(FUNC_NAME))

decoded_bytes = b''
ida_dbg.refresh_debugger_memory()

ea = here()

f = open('config-decrypted.txt', 'a')

try:
    for i in range(MAX):
        buf = Appcall.byref("\x00" * 256)
        ret = decode_func(ea + i, buf)
        print(hex(ea + i))
        buf_addr = idc.read_dbg_dword(ret + BUF_OFFSET)
        decoded_bytes = idc.get_strlit_contents(buf_addr, -1, STRTYPE_C_16)
        if decoded_bytes is None:
            continue
        decoded_bytes2 = decoded_bytes.decode('utf-8')
        match = ALPHA_NUM_CHAR.match(decoded_bytes2)
        if match is not None:
            idc.set_cmt(ea + i, decoded_bytes.decode(), 1)
            print("Decrypted String is \"%s\"" % decoded_bytes.decode())
            f.write(decoded_bytes.decode() + '\n')
        
    ida_kernwin.jumpto(ea)

except:
    print("Exception Error!")
    f.close()

f.close()