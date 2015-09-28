import hexdump  # doing hexdumps obv
import pefile  # easy information about PE file
from capstone import *  # capstone lib for OPcodes


def get_hexdump_from_file(filename):
    filehandle = open(filename)  # open binary for disassembly
    filecontent = filehandle.read()
    filehandle.close()

    filedump = hexdump.dump(filecontent, size=2, sep='\\x')  # hexdump of binary
    # print(hexdump.hexdump(filecontent))
    filedumpasshell = '\\x'+filedump
    return filedumpasshell


def get_entry_point(filename):
    pe = pefile.PE(filename)
    baseofcode = pe.OPTIONAL_HEADER.BaseOfCode
    entrypointoffset = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    return baseofcode+entrypointoffset  # compute entrypoint


def do_disassembly(hexdump_in, offset):
    md = Cs(CS_ARCH_X86, CS_MODE_32)  # set architecture to x86, 32 bit
    for i in md.disasm(hexdump_in, offset):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))  # print linear disassembled opcodes


def address_to_string_pointer(address):
    return address*2*2  # map entrypoint to hexstring (*2 because bytewise and *2 for '\x' in string)

if __name__ == '__main__':
    file_to_analyze = 'res/crackme2.exe'  # todo: as arg

    hexdump = get_hexdump_from_file(file_to_analyze)  # dump file
    entry_point = get_entry_point(file_to_analyze)  # get entry point as int
    # print('EntryPoint: ' + str(hex(entry_point)))  # todo: aber eigentlich offset bei 530 hier..warum?

    pointer_on_string = address_to_string_pointer(entry_point)
    mainfunc = hexdump[pointer_on_string:pointer_on_string+46]
    do_disassembly(mainfunc, entry_point)
