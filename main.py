import pefile  # easy information about PE file like entrypoint
import capstone   # capstone lib for OPcodes
import Queue  # queue module for recursive attempt
import threading  # threading module for some performance optimizations
import binascii  # using for hexdump
# import json  # json is used for saving the results of the disassembler


def get_hexdump_from_file(filename):
    filehandle = open(filename)  # open binary for disassembly
    filecontent = filehandle.read()
    filehandle.close()
    filedump = binascii.hexlify(filecontent)
    print(filedump)
    return filedump


def get_entry_point(filename):
    pe = pefile.PE(filename)
    # imagebase = pe.OPTIONAL_HEADER.ImageBase
    entrypointoffset = str(hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
    return remove_hexprefix(entrypointoffset)


def do_disassembly(offset):  # offset: begin of basic block
    mode = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)  # set architecture to x86 (32 bit)
    # iterate over hex until call/jmp/return ->
    # queue all call dest/jmp dest/ret dest AND condit. branches (both dests!)
    address_ptr = offset

    if address_ptr not in address_map:  # is address allready visited?
        string_ptr = address_to_string_pointer(address_ptr)

        address_map.append(address_ptr)  # if not, mark now as visited
        tmp_hexdump = binascii.a2b_hex(full_hexdump[string_ptr:string_ptr+14])  # todo: how long? 10 byte max length?

        for i in mode.disasm(tmp_hexdump, 0x1000):
            for byte in i.bytes:
                print("%x" % byte)

            print("Size:%x ##\t0x%x:\t%s\t%s" % (i.size, i.address, i.mnemonic, i.op_str))  # todo: save as json

            if i.mnemonic == 'js':  # todo: call and other jumps..
                dsm_queue.put(remove_hexprefix(i.op_str))  # is operation jump/function call? add address to queue!
            else:
                dsm_queue.put(address_ptr + i.size)  # ptr to next instruction


def remove_hexprefix(hexstr):
    return int(hexstr[2:len(hexstr)])


def address_to_string_pointer(address):
    return address*2  # map entrypoint to hexstring (*2 because bytewise)


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

    first_entry_point = get_entry_point(file_to_analyze)  # find a starting point..
    dsm_queue.put(first_entry_point)  # ..and put it in the queue
    dsm_queue.join()  # wait for all jobs to finish

    print(address_map)
