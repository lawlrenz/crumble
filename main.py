import hexdump  # doing hexdumps from binaries obviously
import pefile  # easy information about PE file like entrypoint
import capstone   # capstone lib for OPcodes
import Queue  # queue module for recursive attempt
import threading  # threading module for some performance optimizations
# import json  # json is used for saving the results of the disassembler


def get_hexdump_from_file(filename):
    filehandle = open(filename)  # open binary for disassembly
    filecontent = filehandle.read()
    filehandle.close()

    filedump = hexdump.dump(filecontent, size=2, sep='\\x')  # hexdump of binary
    # print(hexdump.hexdump(filecontent))
    filedumpasshell = '\\x'+filedump  # make sure that the dump is in a readable format for capstone
    return filedumpasshell


def get_entry_point(filename):
    pe = pefile.PE(filename)
    baseofcode = pe.OPTIONAL_HEADER.BaseOfCode
    entrypointoffset = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    return baseofcode+entrypointoffset  # compute entrypoint


def do_disassembly(offset):  # offset: begin of basic block
    mode = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)  # set architecture to x86 (32 bit)

    # iterate over hex until call/jmp/return ->
    # queue all call dest/jmp dest/ret dest AND condit. branches (both dests!)
    address_ptr = offset
    string_ptr = address_to_string_pointer(address_ptr)

    if address_ptr not in address_map:  # is address allready visited?
        address_map.append(address_ptr)  # if not, mark now as visited
        tmp_hexdump = full_hexdump[string_ptr:string_ptr+64]  # todo: how long? 64bit is wrong obv
        for i in mode.disasm(tmp_hexdump, address_ptr):
            if i.mnemonic == 'js':  # todo: call and other jumps..
                address_as_int = int(i.op_str, 0)
                dsm_queue.put(address_as_int)  # is operation jump/function call? add address to queue!
            # else:
                # print("0x%x:\t%s\t%s\n" % (i.address, i.mnemonic, i.op_str))  # todo: save as json
                # print(i.disp)


def address_to_string_pointer(address):
    return address*2*2  # map entrypoint to hexstring (*2 because bytewise and *2 for '\x' in string)


def worker():
    while True:
        entry_point = dsm_queue.get()
        do_disassembly(entry_point)
        dsm_queue.task_done()

if __name__ == '__main__':
    file_to_analyze = 'res/crackme2.exe'  # todo: as arg
    num_threads = 1  # todo: as arg

    address_map = []  # saves allready visited control flow adresses
    dsm_queue = Queue.Queue()  # initialize disassembly queue
    for i in range(num_threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()

    full_hexdump = get_hexdump_from_file(file_to_analyze)  # dump file

    first_entry_point = get_entry_point(file_to_analyze)  # find a starting point.. todo: not sure about that one
    dsm_queue.put(first_entry_point)  # ..and put it in the queue
    dsm_queue.join()  # wait for all jobs to finish
