import hexdump
# import capstone

filehandle = open('a.out')
filecontent = filehandle.read()
filehandle.close()

filedump = hexdump.dump(filecontent)
filedumpasshellcode = hexdump.restore(filedump)
print(filedumpasshellcode)

# for i in capstone.md.disasm(filedump, 0x1000):
#    print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
