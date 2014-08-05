import sys
import ctypes

ropchain = ctypes.cdll.LoadLibrary("./libropchain.so")

f = open(sys.argv[1], 'rb')
binary = f.read()
ropchain.rop_findgadgets(binary, len(binary))
f.close()
