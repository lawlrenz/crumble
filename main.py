import hexdump
from capstone import *

filehandle = open('a.out')
filecontent = filehandle.read()
filehandle.close()

filedump = hexdump.dump(filecontent, size=2, sep='\\x')
filedumpasshell = '\\x'+filedump
print(filedumpasshell)

md = Cs(CS_ARCH_X86, CS_MODE_64)
for i in md.disasm(filedumpasshell, 0x1000):
    print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
