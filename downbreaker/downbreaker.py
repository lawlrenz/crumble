# -*- coding: utf-8 -*-

import pefile  # easy information about PE file like header information
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


def get_entry_point(filename):  # todo: where to start..?
    pe = pefile.PE(filename)
    entrypointoffset = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    # baseofcode = pe.OPTIONAL_HEADER.BaseOfCode
    # sizeofheaders = pe.OPTIONAL_HEADER.SizeOfHeaders
    return entrypointoffset


def do_disassembly(address_ptr_as_int, dsm_queue, address_map, full_hexdump):
    # if beginofbasicblock:
    #    print '====== block at %s ======\n' % hex(address_ptr_as_int)
    indirect_controlflows = 0  # not used yet

    conditional_branch = ['jo', 'jno', 'jb', 'jnae', 'jc', 'jnb', 'jae', 'jnc', 'jz', 'je', 'jnz',
                          'jne', 'jbe', 'jna', 'jnbe', 'ja', 'js', 'jns', 'jp', 'jpe', 'jnp', 'jpo',
                          'jl', 'jnge', 'jnl', 'jge', 'jle', 'jng', 'jnle', 'jg']
    function_call = ['call', 'callf']
    unconditional_branch = ['jmp', 'jmpf']
    return_instr = ['ret']

    hexdump_ptr = get_string_pointer(address_ptr_as_int)
    mode = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)  # set architecture to x86 (32 bit)

    if hex(address_ptr_as_int) not in address_map:  # is address already visited?
        address_map.append(hex(address_ptr_as_int))  # if not, mark now as visited

        inbasicblock = True
        while inbasicblock:
            tmp_hexdump = binascii.a2b_hex(full_hexdump[hexdump_ptr:hexdump_ptr+get_string_pointer(7)])
            if len(list(mode.disasm(tmp_hexdump, address_ptr_as_int))) == 0:
                inbasicblock = False
            else:
                for instruction in mode.disasm(tmp_hexdump, address_ptr_as_int):
                    if instruction.address == address_ptr_as_int:  # process only the first instruction found
                        if instruction.mnemonic in unconditional_branch:
                            print('Unconditional branch')
                            inbasicblock = False
                            if instruction.op_str.find('dword ptr') != -1:
                                indirect_controlflows += 1
                            elif instruction.op_str.find('0x') == -1:
                                indirect_controlflows += 1
                            else:
                                dsm_queue.put(int(instruction.op_str, 16))  # add new entry point to queue

                        elif instruction.mnemonic in function_call:
                            print('Func call')
                            hexdump_ptr += get_string_pointer(instruction.size)
                            if instruction.op_str.find('dword ptr') != -1:
                                indirect_controlflows += 1
                            elif instruction.op_str.find('0x') == -1:
                                indirect_controlflows += 1
                            else:
                                dsm_queue.put(int(instruction.op_str, 16))  # add new entry point to queue

                        elif instruction.mnemonic in conditional_branch:
                            print('Conditional branch')
                            dsm_queue.put(int(instruction.op_str, 16))  # add new entry point to queue
                            hexdump_ptr += get_string_pointer(instruction.size)

                        elif instruction.mnemonic in return_instr:
                            print('Return Instruction')
                            inbasicblock = False
                        else:  # sequential flow
                            print('Sequential flow')
                            hexdump_ptr += get_string_pointer(instruction.size)
                        print "%s\t%s" % (instruction.mnemonic, instruction.op_str)


def get_string_pointer(address):
    return address*2


def worker(dsm_queue, address_map, full_hexdump):
    while True:
        entry_point = dsm_queue.get()
        do_disassembly(entry_point, dsm_queue, address_map, full_hexdump)
        dsm_queue.task_done()


def find_all(a_str, sub):
    start = 0
    while True:
        start = a_str.find(sub, start)
        if start == -1:
            return
        yield hex(start/2)
        start += len(sub)  # use start += 1 to find overlapping matches


def howto():
    print("%s Version %s\n" % ("Recursive Dissassembler", "0.1"))
    print("Usage: " + sys.argv[0] + " [filename] [number of threads]")


def main():
    if len(sys.argv) != 3:
        howto()
    else:
        file_to_analyze = sys.argv[1]
        num_threads = sys.argv[2]
        address_map = []  # saves already visited adresses

        dsm_queue = Queue.Queue()  # initialize disassembly queue

        full_hexdump = get_hexdump_from_file(file_to_analyze)  # dump_crackme2 file

        for i in range(int(num_threads)):
            t = threading.Thread(target=worker, args=(dsm_queue, address_map, full_hexdump))
            t.daemon = True
            t.start()

        first_entry_point = get_entry_point(file_to_analyze)  # find a starting point..
        print("\nStarting disassembly..\n")

        # print(list(find_all(full_hexdump, "5589e5")))
        # print(list(find_all(full_hexdump, "c2")))

        dsm_queue.put(first_entry_point)  # ..and put it in the queue
        dsm_queue.join()  # wait for all jobs to finish
        # print(address_map)
        print("Successfully disassembled " + str(len(address_map)) + " adresses.")
        # print(sorted(address_map))
        # print("Indirectcontrolflows (not analyzed!): " + str(indirect_controlflows))

        # print("\n")
        # print(output)
