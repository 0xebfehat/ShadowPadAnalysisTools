# decrypt routine for 5f1a21940be9f78a5782879ad54600bd67bfcd4d32085db7a3e8a88292db26cc

import sys
import struct

def decrypt_data(key, size):
    out = []
    for i in range(size - 4):
        key = (key * 0x11) & 0xffffffff
        key = (key + 0x107E666D) & 0xffffffff
        val = ((((key >> 0x18) + (key >> 0x10)) & 0xff) + (key >> 8) & 0xff)
        val = (val + key) & 0xff
        out.append(val ^ cf[i + 4])
    return out

cf = open(sys.argv[1], "rb").read()
sc = open("sc.bin", "wb")

key = struct.unpack('<I', cf[0:4])[0]
out = decrypt_data(key, len(cf))
sc.write(bytearray(out))


