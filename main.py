import pefile  # easy information about PE file like entrypoint
import capstone   # capstone lib for OPcodes
import Queue  # queue module for "recursive" attempt
import threading  # threading module for some performance optimizations
import binascii  # using for hexdump
import sys
# import json  # json is used for saving the results of the disassembly


def get_hexdump_from_file(filename):
    filehandle = open(filename)  # open binary for disassembly
    filecontent = filehandle.read()
    filehandle.close()
    filedump = binascii.hexlify(filecontent)
    return filedump


def get_entry_point(filename):
    pe = pefile.PE(filename)
    entrypointoffset = str(hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
    return remove_hexprefix(entrypointoffset)


def do_disassembly(address_ptr):
    mode = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)  # set architecture to x86 (32 bit)
    # iterate over hex until call/jmp/return ->
    # queue all call dest/jmp dest/ret dest AND condit. branches (both dests!)

    if address_ptr not in address_map:  # is address allready visited?
        string_ptr = address_to_string_pointer(address_ptr)

        address_map.append(address_ptr)  # if not, mark now as visited
        tmp_hexdump = binascii.a2b_hex(full_hexdump[string_ptr:string_ptr+14])  # conv to bin
        # todo: how long? 10 byte max length?
        hexaddr = add_hexprefix(address_ptr)
        for instruction in mode.disasm(tmp_hexdump, hexaddr):
            if instruction.address == hexaddr:  # save only first instruction
                # for byte in i.bytes:
                #    print("%x" % byte)
                # if tmp_hexdump.find('5589e5') > 1:
                #    mark as function start!!
                print("0x%x:\t%s\t%s" % (instruction.address, instruction.mnemonic, instruction.op_str))  # todo: save as json
                if instruction.mnemonic == 'js':  # todo: call and other jumps..
                    dsm_queue.put(remove_hexprefix(instruction.op_str))  # add new entry point to queue
                else:
                    dsm_queue.put(address_ptr + instruction.size)  # ptr to next instruction


def remove_hexprefix(hexstr):  # 0x42 -> 42
    return int(str(hexstr)[2:len(hexstr)])


def add_hexprefix(hexstr_without_prefix):  # 42 (int) -> int(0x42, 16)
    tmp = '0x' + str(hexstr_without_prefix)
    return int(tmp, 16)


def address_to_string_pointer(address):
    return address*2  # map entrypoint to hexstring (*2 because address is bytewise)


def worker():
    while True:
        entry_point = dsm_queue.get()
        do_disassembly(entry_point)
        dsm_queue.task_done()


def howto():
    print("%s Version %s\n" % ("Recursive Dissassembler", "0.1"))
    print("Usage: " + sys.argv[0] + " [filename] [number of threads]")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        howto()
    else:
        file_to_analyze = sys.argv[1]
        num_threads = sys.argv[2]
        address_map = []  # saves allready visited adresses
        dsm_queue = Queue.Queue()  # initialize disassembly queue

        for i in range(int(num_threads)):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()

        full_hexdump = get_hexdump_from_file(file_to_analyze)  # dump_crackme2 file

        first_entry_point = get_entry_point(file_to_analyze)  # find a starting point..
        print("\nStarting disassembyl..\n")
        dsm_queue.put(first_entry_point)  # ..and put it in the queue
        dsm_queue.join()  # wait for all jobs to finish
        # print(address_map)
        print("\nSuccessfully disassembled " + str(len(address_map)) + " adresses.")
