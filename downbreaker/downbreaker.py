# -*- coding: utf-8 -*-

import pefile  # easy information about PE file like header information
import capstone   # capstone lib for OPcodes
import Queue  # queue module for "recursive" attempt
import threading  # threading module for some performance optimizations
import binascii  # using for hexdump
import sys
import json  # json is used for saving the results of the disassembly


def get_hexdump_and_entrypoint_from_file(filename):
    try:
        pe = pefile.PE(filename)
    except OSError:
        sys.exit('The file: ' + filename + ' could not be found.')
    return binascii.b2a_hex(pe.get_memory_mapped_image()), pe.OPTIONAL_HEADER.AddressOfEntryPoint


def do_disassembly(address_ptr, dsm_queue, address_map, full_hexdump):
    indirect_controlflows = 0  # not used yet

    conditional_branch = ['jo', 'jno', 'jb', 'jnae', 'jc', 'jnb', 'jae', 'jnc', 'jz', 'je', 'jnz',
                          'jne', 'jbe', 'jna', 'jnbe', 'ja', 'js', 'jns', 'jp', 'jpe', 'jnp', 'jpo',
                          'jl', 'jnge', 'jnl', 'jge', 'jle', 'jng', 'jnle', 'jg']
    function_call = ['call', 'callf']
    unconditional_branch = ['jmp', 'jmpf']
    return_instr = ['ret']

    mode = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)  # set architecture to x86 (32 bit)

    inbasicblock = True
    startmsg = False
    basicblock = []
    if hex(address_ptr) not in address_map:
        address_map.append(hex(address_ptr))  # mark address as visited

        while inbasicblock:
            if not startmsg:
                # print("### BEGIN OF BASICBLOCK ###")
                startmsg = True

            buff = binascii.a2b_hex(full_hexdump[get_string_pointer(address_ptr):get_string_pointer(address_ptr + 7)])
            if len(list(mode.disasm(buff, address_ptr))) == 0:  # check if end of instructions
                inbasicblock = False
            else:
                address_ptr_first_instruction = address_ptr
                for instruction in mode.disasm(buff, address_ptr):
                    if instruction.address == address_ptr_first_instruction:  # process only the first instruction found
                        if instruction.mnemonic in unconditional_branch:
                            # print('Unconditional branch')
                            inbasicblock = False
                            if instruction.op_str.find('dword ptr') != -1:
                                indirect_controlflows += 1
                            elif instruction.op_str.find('0x') == -1:
                                indirect_controlflows += 1
                            else:
                                dsm_queue.put(int(instruction.op_str, 16))  # add new entry point to queue

                        elif instruction.mnemonic in function_call:
                            # print('Func call')
                            address_ptr += instruction.size
                            if instruction.op_str.find('dword ptr') != -1:
                                indirect_controlflows += 1
                            elif instruction.op_str.find('0x') == -1:
                                indirect_controlflows += 1
                            else:
                                dsm_queue.put(int(instruction.op_str, 16))  # add new entry point to queue

                        elif instruction.mnemonic in conditional_branch:
                            # print('Conditional branch')
                            inbasicblock = False
                            dsm_queue.put(address_ptr + instruction.size)  # add new entry point to queue
                            dsm_queue.put(int(instruction.op_str, 16))  # add new entry point to queue

                        elif instruction.mnemonic in return_instr:
                            # print('Return Instruction')
                            inbasicblock = False
                        else:
                            # print('Sequential flow')
                            address_ptr += instruction.size
                        # byteseq = binascii.b2a_hex(instruction.bytes)
                        # byteseq = " ".join(byteseq[i:i+2] for i in range(0, len(byteseq), 2))
                        # print "0x%x:\t%s\n\t%s\t%s" \
                        #      % (instruction.address, byteseq, instruction.mnemonic, instruction.op_str)
                        disassembled = instruction.mnemonic + ' ' + instruction.op_str
                        basicblock.append(disassembled)
            # if not inbasicblock:
            #    print("### END OF BASICBLOCK ###")
        print(json.dumps({'basicblock': basicblock}))  # testing


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
        start += len(sub)


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
        full_hexdump, first_entry_point = get_hexdump_and_entrypoint_from_file(file_to_analyze)

        for i in range(int(num_threads)):
            t = threading.Thread(target=worker, args=(dsm_queue, address_map, full_hexdump))
            t.daemon = True
            t.start()

        print("\nStarting disassembly..\n")

        # print(list(find_all(full_hexdump, "5589e5")))
        # print(list(find_all(full_hexdump, "c2")))

        dsm_queue.put(first_entry_point)
        dsm_queue.join()  # wait for all jobs to finish

        # print(address_map)
        print("Successfully disassembled " + str(len(address_map)) + " Basicblocks.")
