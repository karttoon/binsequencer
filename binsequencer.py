#!/usr/bin/env python3
import sys, argparse, time, os, re, binascii

try:
    import yara
except:
    print("\n   [!] Please install the Python 'yara' module")
    sys.exit(1)

try:
    import pefile
except:
    print("\n    [!] Please install the Python 'pefile' module")
    sys.exit(1)

try:
    from capstone import *
except:
    print("\n    [!] Please install the Python 'capstone' module")
    sys.exit(1)

__author__  = "Jeff White [karttoon] @noottrak"
__email__   = "karttoon@gmail.com"
__version__ = "1.0.8"
__date__    = "05SEP2019"

#
# The data structure used throughout this program is below:
#
#   data {
#       hash {
#           "op_blob": {
#               "section0": "jmp|ret|nop"
#               "section1": "mov|add|sub"
#           "op_offset": {
#               "section0": ["0x10001000:   jmp | e9 ?? ?? ??", "0x10001001:  ret | c3"]
#               "section1": ["0x10003000:   mov | bf ?? ??", "0x10003001:  add | 83"]
#           "op_chain": {
#               "section0": ["jmp", "ret"]
#               "section1": ["mov", "add"]
#           "section_name": {
#               "section0": ".text"
#               "section1": ".code"
#       "gold": hash
#       "matches": {
#           op_blob: {
#               "count"  : int_match_count
#               "hashes" : ["hash", "hash"]
#       "sets" {
#           "longest" : {
#               "section0": 154
#               "section1": 25
#       "yara" {
#           "rule1" : {
#               "start"  : "0x10001700"
#               "end"    : "0x10001afe"
#               "hashes" : ["hash", "hash"]
#               "bytes"  : "e9010203bf010203c383"
#               "result" : "e9 ?? ?? ?? bf ?? ?? c3 83"
#               "msg"    : "Status messages"
#       "blacklist" : [op_blob, op_blob]
#       "keeplist"  : [op_blob, op_blob]
#       "strings"   : ["string1", "string2"]
#

################
# User Prompts #
################
def user_prompt(usr_msg):

    user_response = (input(usr_msg)).upper()

    if user_response == "Y":
        return "Y"
    else:
        return "N"

def print_asst(msg, args):

    if not args.quiet:
        print(msg)

    return

#################
# Process Files #
#################
def process_pe(hash, data, args):

    pe          = pefile.PE(hash)
    count       = 0
    data[hash]  = {"op_blob": {}, "op_offset": {}, "op_chain": {}, "section_name": {}} # Initialize each hash dictionary

    print_asst("\t[-]" + hash, args)

    for section in pe.sections:

        if section.IMAGE_SCN_CNT_CODE == True or section.IMAGE_SCN_MEM_EXECUTE == True: # Only work on code sections

            section_start   = 0
            zero_check      = binascii.hexlify(pe.sections[count].get_data()[0:2]).decode("ascii")

            # This loop will move the start forward until it no longer begins with null bytes
            # Idea is to try and get to valid bytes in the code section for disassembly without using EP
            while zero_check == "0000":

                if args.verbose == True:
                    print_asst("debug zc %s" % zero_check, args)

                section_start   += 4
                zero_check      = binascii.hexlify(pe.sections[count].get_data()[section_start:section_start + 2]).decode("ascii")

            if args.verbose == True:
                print_asst("debug section start %s" % section_start, args)

            op_blob                                 = "" # Initialize opcode blob
            instruction_count                       = 0 # Count for maximum number of ops
            section_value                           = "section%d" % len(data[hash]["op_blob"])
            data[hash]["op_blob"][section_value]    = ""
            data[hash]["op_offset"][section_value]  = []
            data[hash]["op_chain"][section_value]   = []

            code_section    = pe.sections[count].get_data()[section_start:section.SizeOfRawData]
            virt_addr       = pe.sections[count].VirtualAddress
            for op in md.disasm(code_section, int(hex(virt_addr), 16) + 0x10000000 + int(hex(section_start), 16)):

                op_blob += "%s|" % op.mnemonic
                data[hash]["op_offset"][section_value].append("0x%x:\t%s |%s" % (op.address, op.mnemonic, "".join('{:02x}'.format(x) for x in op.bytes)))
                data[hash]["op_chain"][section_value].append("%s" % op.mnemonic)

                if args.verbose == True:
                    if hasattr(op, "bytes"):
                        print_asst("debug %x | %-15s | %-15s | %2d | %-10s | %-15s | %-12s | %s" % (op.address, op.prefix, op.opcode, len(op.operands), op.mnemonic, op.op_str, "".join('{:02x}'.format(x) for x in op.bytes), "1"), args)

                instruction_count += 1

            data[hash]["op_blob"][section_value]        = op_blob
            data[hash]["section_name"][section_value]   = section.Name.decode("ascii")

            print_asst("\t\t%s - %d instructions extracted" % (section.Name.decode("ascii"), instruction_count), args)

        count += 1 # Count for each section processed

    # Remove files with no instructions identified
    count = 0
    for entry in data[hash]["op_chain"]:
        if data[hash]["op_chain"][entry] == []:
            count += 1

    if count == len(data[hash]["op_chain"]):
        print_asst("\t\t\t[!] Removed due to no extracted instructions", args)
        del data[hash]

    return data

def process_nonpe(hash, data, args):

    file_data = open(hash, "rb").read().strip() # Remove newline - usually an issue with copy/paste shellcode
    data[hash] = {"op_blob": {}, "op_offset": {}, "op_chain": {}, "section_name": {}}  # Initialize each hash dictionary

    print_asst("\t[-]" + hash, args)

    op_blob = ""  # Initialize opcode blob
    instruction_count = 0  # Count for maximum number of ops
    data[hash]["op_blob"]["section0"] = ""
    data[hash]["op_offset"]["section0"] = []
    data[hash]["op_chain"]["section0"] = []

    code_section = file_data
    virt_addr = 0x0
    for op in md.disasm(code_section, int(hex(virt_addr), 16) + 0x10000000 + int(hex(0), 16)):

        # if hasattr(op, "_detail"):
        if hasattr(op, "bytes"):
            op_blob += "%s|" % op.mnemonic
            data[hash]["op_offset"]["section0"].append("0x%x:\t%s |%s" % (op.address, op.mnemonic, "".join('{:02x}'.format(x) for x in op.bytes)))
            data[hash]["op_chain"]["section0"].append("%s" % op.mnemonic)

        if args.verbose == True:
            if hasattr(op, "bytes"):
                print_asst("debug %x | %-15s | %-15s | %2d | %-10s | %-15s | %-12s | %s" % (op.address, op.prefix, op.opcode, len(op.operands), op.mnemonic, op.op_str,  "".join('{:02x}'.format(x) for x in op.bytes), "1"), args)

        instruction_count += 1

    data[hash]["op_blob"]["section0"] = op_blob
    data[hash]["section_name"]["section0"] = "nonpefile"

    print_asst("\t\t%s - %d instructions extracted" % ("nonpefile", instruction_count), args)

    return data

def process_files(hash, data, args):

    data[hash]  = {} # Initialize hash dictionary

    if not args.nonpe:
        try:
            pefile.PE(hash)
            data = process_pe(hash, data, args)
        except:
            del data[hash]
    else:
        data = process_nonpe(hash, data, args)

    return data

######################
# Identify Gold Hash #
######################
def find_gold(hashes, data, args):

    instruction_count = 0

    if len(hashes) == 0:
        print_asst("[!] No files loaded. Please use (-n) flag for non-PE files\n", args)
        sys.exit(1)

    for hash in hashes:

        if len(hashes) == 1:

            gold_hash = hash

        section_count = 0

        try:
            for section_name in data[hash]["section_name"]:
                section_count += len(data[hash]["op_chain"][section_name])
        except:
            print_asst("[!] Unable to find section data. Please use (-n) flag for non-PE files\n", args)
            sys.exit(1)

        # If 100% commonality, gold hash will be the hash with lowest amount of opcodes
        if args.commonality == 1.0:

            if instruction_count == 0:
                instruction_count   = section_count
                gold_hash           = hash

            if section_count < instruction_count:
                instruction_count   = section_count
                gold_hash           = hash

            if args.verbose == True:
                print_asst("debug hash %s sec_count %d instruction_count %d gold %s" % (hash, section_count, instruction_count, gold_hash), args)

        # If not a 100% commonality, gold hash will be the hash with the highest amount of opcodes
        else:
            if section_count > instruction_count:
                instruction_count   = section_count
                gold_hash           = hash

    # If gold specified via argument, use it
    if args.gold:
        for hash in hashes:
            if args.gold.replace("'","") in hash:
                data["gold"] = hash
    else:
        data["gold"] = gold_hash

    print_asst("\n[+] Golden hash (%d instructions) - %s" % (instruction_count, data["gold"]), args)

    return data

########################
# Identify Longest Set #
########################
def longest_match(hashes, data, args):

    section_total = len(data[data["gold"]]["section_name"])
    section_count = 0

    while section_count < section_total:

        # Stop processing subsequent sections if match count is met
        if len(data["keeplist"]) >= args.matches:
            break

        section_value   = "section" + str(section_count)
        initial_size    = len(data[data["gold"]]["op_chain"][section_value])

        print_asst("\n[+] Zeroing in longest mnemonic instruction set in %s\n" % data[data["gold"]]["section_name"][section_value], args)

        # YARA has a limit on the number of hex tokens (10K) so we artificially limit our size
        # Minimum 1 byte per instruction, usually 2-5 bytes for operands, but we'll have additional logic to cut hex off if it goes further
        if initial_size > 4000:
            blob_size = 4000
        else:
            blob_size = initial_size

        if initial_size == 0:
            print_asst("\t[-] No instructions in this section", args)

        max_size        = blob_size
        delta_value     = int(blob_size / 2)
        closing_flag    = 0

        while blob_size > 0:

            start   = time.time()
            data    = find_match(hashes, data, blob_size, section_value, args)
            end     = time.time()

            # Validate number of instructions in blob are longer than minimum - 25 has been fairly reliable for a default
            # Figure prologue / epilogue will be around 6 instructions alone
            if blob_size < args.length and section_count != (section_total - 1):
                break

            # If we have no matches, all sections have been checked, exit
            if len(data["matches"]) == 0 and blob_size < args.length and section_count == (section_total - 1) and len(data["keeplist"]) == 0:

                print_asst("\n\t[!] Unable to match set above the minimum count\n\tConsider adjusting lower with -l flag or adjusting sample set with -c\n", args)
                sys.exit(1)

            # If the size is maxed out and matched, immediately go into review
            if len(data["matches"]) >= 1 and blob_size == max_size:

                print_asst("\t[-] Moving %d instruction sets to review with a length of %d" % (len(data["matches"]), blob_size), args)

                data = check_match(data, args, "longest", section_value)

                # If match has been blacklisted, remove it
                for match in data["blacklist"]:
                    data["matches"].pop(match, None)

                # If we've hit our match cap, move on
                if len(data["keeplist"]) >= args.matches or len(data["matches"]) > 0:

                    data["matches"] = {}
                    break

                # If all matches removed, continue the hunt
                if len(data["matches"]) == 0 or len(data["keeplist"]) < args.matches:

                    closing_flag    = 0
                    blob_size       = int(blob_size / 2)
                    delta_value     = int(blob_size / 2)
                    data["matches"] = {}

                    print_asst("", args) # Spacing

                else:
                    break # Go to next section

            print_asst("\t[-] Matches - %-5d Block Size - %-5d Time - %0.2f seconds" % (len(data["matches"]), blob_size, end-start), args)

            if args.verbose == True:
                print_asst("debug - ins size %d, # of matches %d, closing_flag %d, delta %d" % (blob_size, len(data["matches"]), closing_flag, delta_value), args)

            # Shrinks blob size by half and begins dividing delta
            if len(data["matches"]) == 0 and delta_value != 0:

                blob_size   = blob_size - delta_value
                delta_value = int(delta_value / 2)

            # Grows blob size by adding half of the delta to existing size
            if len(data["matches"]) >= 1 and delta_value != 0:

                blob_size       = blob_size + delta_value
                delta_value     = int(delta_value / 2)
                data["matches"] = {}

            # If previous run had a match and set the closing flag, this will trigger once there are no more matches
            # Subtract one from the existing size to find longest
            if len(data["matches"]) == 0 and delta_value == 0 and closing_flag == 1:

                blob_size   = blob_size - 1
                data        = find_match(hashes, data, blob_size, section_value, args)

                # Validate we still haven't fallen below our minimum length
                if blob_size >= args.length:

                    print_asst("\n\t[-] Moving %d instruction sets to review with a length of %d" % (len(data["matches"]), blob_size), args)

                    data = check_match(data, args, "longest", section_value)

                else:

                    print_asst("\t[!] Unable to meet the minimum match count, continuing with remaining sets", args)
                    break

                # If we've hit our match cap, move on
                if len(data["keeplist"]) >= args.matches:

                    data["matches"] = {}
                    break

                # If match has been blacklisted, remove it
                for match in data["blacklist"]:
                    data["matches"].pop(match, None)

                # If all matches removed, continue the hunt
                if len(data["matches"]) == 0:

                    closing_flag    = 0
                    blob_size       = int(blob_size / 2)
                    delta_value     = int(blob_size / 2)
                    data["matches"] = {}

                    print_asst("", args) # Spacing

                else:
                    break # Go to next section

            # Continue increasing by one until we no longer have matches
            if len(data["matches"]) >= 1 and delta_value == 0:

                blob_size       += 1
                closing_flag    = 1
                data["matches"] = {}

            # If we've run out of our delta with no matches, we'll be above our target, so we need to reduce by one until we match
            if len(data["matches"]) == 0 and delta_value == 0 and closing_flag == 0:

                blob_size       -= 1
                data["matches"] = {}

        section_count += 1

    # Validate we have matches, otherwise exit program
    if len(data["keeplist"]) >= 1:
        print_asst("\n[+] Keeping %d mnemonic set using %d %% commonality out of %d hashes\n" % (len(data["keeplist"]), args.commonality * 100, len(hashes)), args)

    else:
        print_asst("\t[!] Unable to match set above the minimum count\n\tConsider adjusting lower with -l flag or adjusting sample set with -c\n", args)
        sys.exit(1)

    for section in data["sets"]["longest"]:
        print_asst("\t[-] Length - %-5d Section - %s" % (data["sets"]["longest"][section], data[data["gold"]]["section_name"][section]), args)

    if args.verbose == True:
        print_asst("debug sets %s" % data["sets"], args)

    return data

#########################
# Find Instruction Sets #
#########################
def find_match(hashes, data, opset_size, section_value, args):

    slider_start    = 0
    slider_end      = int(opset_size + slider_start)
    slider_length   = int(opset_size)

    while slider_length == opset_size: # breaks once we go outside of possible range

        if args.verbose == True:
            print_asst("debug - slider start %d, end %d, len %d, size %d" % (slider_start, slider_end, slider_length, opset_size), args)

        instruction_blob    = "|".join(data[data["gold"]]["op_chain"][section_value][slider_start:slider_end]) # instruction size - 1 if you count pipes
        disregard_value     = 0
        first_run           = 0
        hash_count          = 0
        match_count         = 0

        for hash in hashes:

            if len(hashes) == 1:

                hash_count = 1
                data, disregard_value, first_run, hash_count, match_count, opset_size = find_data(data,
                                                                                                  args,
                                                                                                  hash,
                                                                                                  instruction_blob,
                                                                                                  disregard_value,
                                                                                                  first_run,
                                                                                                  hash_count,
                                                                                                  match_count,
                                                                                                  opset_size)

            else:

                if hash != data["gold"]:  # Don't run it against gold, since it will match everything

                    hash_count += 1
                    data, disregard_value, first_run, hash_count, match_count, opset_size = find_data(data,
                                                                                                      args,
                                                                                                      hash,
                                                                                                      instruction_blob,
                                                                                                      disregard_value,
                                                                                                      first_run,
                                                                                                      hash_count,
                                                                                                      match_count,
                                                                                                      opset_size)

                    # Exponentially increases speed, breaks iteration loop once match count dips below minimum criteria
                    if (float(match_count) / float(hash_count)) < args.commonality:
                        break

        # Remove blob from matches if we drop below the minimum criteria
        if instruction_blob in data["matches"].keys() and (float(data["matches"][instruction_blob]["count"])/float(len(hashes))) < args.commonality:

            data["matches"].pop(instruction_blob, None)

            if args.verbose == True:
                print_asst("debug break instruction size in keys %d" % opset_size, args)

        # Advances window by one and will cause loop to break towards end of window, when length drops below the size
        slider_start    += 1
        slider_end      = opset_size + slider_start
        slider_length   = len(data[data["gold"]]["op_chain"][section_value][slider_start:slider_end])

    return data

def find_data(data, args, hash, instruction_blob, disregard_value, first_run, hash_count, match_count, opset_size):

    for section in data[hash]["section_name"]:  # Check for blob in all code executable sections

        # See if the instruction blob exists within other hashes blobs
        line_check = data[hash]["op_blob"][section].find(instruction_blob)

        # Line check will be -1 if it doesn't find a match
        if line_check >= 0 and first_run == 0:

            # Validate the instruction blob is not found within a blacklisted instruction set
            for match in data["blacklist"]:
                if instruction_blob in match:
                    disregard_value = 1

            # First match across the samples
            if disregard_value == 0:

                data["matches"][instruction_blob] = {"count": 2, "hashes": [hash, data["gold"]]}
                first_run = 1
                match_count += 1

                if args.verbose == True:
                    print_asst("debug break instruction size found first %d" % opset_size, args)

        # Subsequent matches
        elif line_check >= 0 and first_run == 1:

            data["matches"][instruction_blob]["hashes"].append(hash)
            data["matches"][instruction_blob]["count"] += 1
            match_count += 1

    return data, disregard_value, first_run, hash_count, match_count, opset_size

#################
# Check Matches #
#################
def check_pe(data, match, args, match_section, set_match):

    display_flag = 0
    keep_flag    = 0
    count        = 0
    pe           = pefile.PE(data["gold"])

    for pe_section in pe.sections:

        if len(data["matches"]) > 0 and match not in data["blacklist"]:

            if pe_section.Name.decode("ascii") == data[data["gold"]]["section_name"][match_section]:

                # For multiple sections, make sure we don't keep prompting
                if args.default:
                    user_answer = "N"
                else:
                    if display_flag == 0:
                        user_answer = user_prompt("\n    [*] Do you want to display matched instruction set? [Y/N] ")

                if user_answer == "N":
                    display_flag = 1

                if user_answer == "Y" or display_flag == 0:
                    print_asst("\n\t%s" % match, args)
                    display_flag = 1

                    user_answer = user_prompt("\n    [*] Do you want to disassemble the underlying bytes? [Y/N] ")
                    if user_answer == "Y":

                        byte_list = []
                        string_start = data[data["gold"]]["op_blob"][match_section].find(match)  # Find offset of match in blob

                        if string_start == 0:
                            pre_match = 0
                        else:
                            pre_match = (data[data["gold"]]["op_blob"][match_section][0:string_start].count("|"))

                        match_start = (data[data["gold"]]["op_offset"][match_section][pre_match]).split(":")[0]
                        match_end = (data[data["gold"]]["op_offset"][match_section][pre_match + len(set_match) - 1]).split(":")[0]
                        scrape_flag = 0

                        print_asst("", args)  # Spacing

                        code_section = pe.sections[count].get_data()[:pe_section.SizeOfRawData]
                        virt_addr = pe.sections[count].VirtualAddress
                        for op in md.disasm(code_section, int(hex(virt_addr), 16) + 0x10000000):

                            # Due to a Capstone bug, sometimes object won't have '_detail' which causes an infinite recursive loop and crash
                            #if hasattr(op, "_detail"):
                            if hasattr(op, "bytes"):

                                # Start of match
                                if op.address == int(match_start, 16) or scrape_flag == 1:
                                    scrape_flag = 1
                                    byte_array = "".join('{:02x}'.format(x) for x in op.bytes)
                                    byte_list.append(byte_array)

                                    print_asst("\t0x%x:\t%-10s %-40s | %s" % (op.address, op.mnemonic, op.op_str, byte_array.upper()), args)

                                if op.address == int(match_end, 16):
                                    break

                            # Print raw bytes in the event it doesn't disassemble
                            else:
                                if scrape_flag == 1:
                                    byte_array = "".join('{:02x}'.format(x) for x in op.bytes)
                                    byte_list.append(byte_array)

                                    print_asst("\tDATA:\t%s" % (byte_array.upper()), args)

                        user_answer = user_prompt("\n    [*] Do you want to display the raw byte blob? [Y/N] ")
                        if user_answer == "Y":
                            print_asst("\n\t%s" % ("".join(byte_list)).upper(), args)

                # For multiple sections, make sure we don't keep prompting
                if keep_flag == 0:
                    keep_flag = 1

                    if args.default:
                        user_answer = "Y"
                    else:
                        user_answer = user_prompt("\n    [*] Do you want to keep this set? [Y/N] ")

                    if user_answer == "N" or match in data["blacklist"]:
                        data["blacklist"].append(match)

                    # Matched result
                    else:
                        data["sets"]["longest"][match_section] = len(set_match)
                        data["keeplist"][match] = data["matches"][match]
                        data["blacklist"].append(match)

                # If accepted number of rules equals minimum, go ahead and stop
                if len(data["keeplist"]) >= args.matches:
                    for match in data["matches"]:
                        data["blacklist"].append(match)
                    return data

        if pe_section.IMAGE_SCN_CNT_CODE == True or pe_section.IMAGE_SCN_MEM_EXECUTE == True:
            count += 1

    return data

def check_nonpe(data, match, args, match_section, set_match):

    display_flag = 0
    keep_flag    = 0

    if len(data["matches"]) > 0 and match not in data["blacklist"]:

        # For multiple sections, make sure we don't keep prompting
        if args.default:
            user_answer = "N"
        else:
            if display_flag == 0:
                user_answer = user_prompt("\n    [*] Do you want to display matched instruction set? [Y/N] ")

        if user_answer == "N":
            display_flag = 1

        if user_answer == "Y" or display_flag == 0:
            print_asst("\n\t%s" % match, args)
            display_flag = 1

            user_answer = user_prompt("\n    [*] Do you want to display the raw byte blob? [Y/N] ")
            if user_answer == "Y":

                byte_list = []
                string_start = data[data["gold"]]["op_blob"][match_section].find(match)  # Find offset of match in blob

                if string_start == 0:
                    pre_match = 0
                else:
                    pre_match = (data[data["gold"]]["op_blob"][match_section][0:string_start].count("|"))

                match_start = int((data[data["gold"]]["op_offset"][match_section][pre_match]).split(":")[0], 16) - 0x10000000
                match_end = int((data[data["gold"]]["op_offset"][match_section][pre_match + len(set_match) - 1]).split(":")[0], 16) - 0x10000000
                scrape_flag = 0

                print_asst("", args)  # Spacing

                code_section = open(data["gold"], "rb").read()[match_start:match_end + 1] # Remove newline typical in shellcode copy/paste files
                virt_addr = 0x0

                for op in md.disasm(code_section, int(hex(virt_addr), 16) + 0x10000000):

                    # Due to a Capstone bug, sometimes object won't have '_detail' which causes an infinite recursive loop and crash
                    #if hasattr(op, "_detail"):
                    if hasattr(op, "bytes"):

                        # Start of match
                        if op.address == (match_start + 0x10000000) or scrape_flag == 1:
                            scrape_flag = 1
                            byte_array = "".join('{:02x}'.format(x) for x in op.bytes)
                            byte_list.append(byte_array)

                            print_asst(
                                "\t0x%x:\t%-10s %-40s | %s" % (op.address, op.mnemonic, op.op_str, byte_array.upper()),
                                args)

                        if op.address == (match_end + 0x10000000):
                            break

                    # Print raw bytes in the event it doesn't disassemble
                    else:
                        if scrape_flag == 1:
                            byte_array = "".join('{:02x}'.format(x) for x in op.bytes)
                            byte_list.append(byte_array)

                            print_asst("\tDATA:\t%s" % (byte_array.upper()), args)

                print_asst("\n\t%s" % ("".join(byte_list)).upper(), args)

        # For multiple sections, make sure we don't keep prompting
        if keep_flag == 0:
            keep_flag = 1

            if args.default:
                user_answer = "Y"
            else:
                user_answer = user_prompt("\n    [*] Do you want to keep this set? [Y/N] ")

            if user_answer == "N" or match in data["blacklist"]:
                data["blacklist"].append(match)

            # Matched result
            else:
                data["sets"]["longest"][match_section] = len(set_match)
                data["keeplist"][match] = data["matches"][match]
                data["blacklist"].append(match)

        # If accepted number of rules equals minimum, go ahead and stop
        if len(data["keeplist"]) >= args.matches:
            for match in data["matches"]:
                data["blacklist"].append(match)
            return data

    return data

def check_match(data, args, function, match_section):

    for match in data["matches"]:

        set_match       = match.split("|")

        # Blacklist any sets with lower than 3 types
        # Double NULL bytes (00 00) will disassemble to "add byte ptr [eax], al"
        # Some matches append or preprend one instruction to a NULL byte run
        if len(list(set(set_match))) <= 3:
            data["blacklist"].append(match)
            print_asst("\t[!] Blacklisted a potentially bad match", args)

        if args.verbose == True:
            print_asst("debug # of matches %d - %d long - %d match" % (len(data["matches"]), match.count("|") + 1, len(set_match)), args)

        # Routine to review match
        if function == "longest":

            if args.nonpe:
                data = check_nonpe(data, match, args, match_section, set_match)
            else:
                pefile.PE(data["gold"])
                data = check_pe(data, match, args, match_section, set_match)


    # Black list remaining matches (these were not kept)
    for match in data["matches"]:
        if match in data["blacklist"]:
            data["blacklist"].append(match)

    return data

###################################
# Print Match Offsets By Function #
###################################

def print_offset(data, args):

    for type in data["sets"]:

        print_asst("\n[+] Printing offsets of type: %s" % type, args)

        for section in data["sets"][type]:

            print_asst("\n\t[-] Gold matches", args)
            find_offset(data, args, "gold")

            print_asst("\n\t[-] Remaining matches", args)
            find_offset(data, args, "others")

    return

######################
# Find Match Offsets #
######################

def find_offset(data, args, run_type):

    match_count = 0

    for match in data["keeplist"]:

        set_match = match.split("|")
        hash_list = []

        # Handle the gold hash first
        if run_type == "gold":
            hash_list = [data["gold"]]

            print_asst("\n\t----------v SET rule%d v----------\n\t%s\n\t----------^ SET rule%d ^-----------\n" % (match_count, match, match_count), args)

        else:
            for hash in data["keeplist"][match]["hashes"]:
                if hash != data["gold"]:
                    hash_list.append(hash)

        # Remaining matches
        if run_type != "gold":
            print_asst("\n\t----------v SET rule%d v----------" % (match_count), args)

        for hash in hash_list:
            for section in data[hash]["section_name"]:

                try:

                    string_start = data[hash]["op_blob"][section].find(match) # Find offset of match in blob

                    if string_start == 0:
                        pre_match = 0
                    else:
                        pre_match = (data[hash]["op_blob"][section][0:string_start].count("|"))

                    match_start = (data[hash]["op_offset"][section][pre_match]).split(":")[0]
                    match_end   = (data[hash]["op_offset"][section][pre_match + len(set_match) - 1]).split(":")[0]

                    if args.verbose == True:
                        print_asst("debug offset %d pre %d start %s end %s" % (string_start, pre_match, match_start, match_end), args)

                    print_asst("\t\t%-100s %s - %s in %s" % (hash, match_start, match_end, data[hash]["section_name"][section]), args)

                    # Record offset for gold hash to use later
                    if hash == data["gold"]:
                        data["yara"]["rule" + str(match_count)] = {"start":match_start, "end":match_end, "hashes":data["keeplist"][match]["hashes"]}

                        if args.verbose == True:
                            print_asst("debug match blob %s " % (" ".join(data[hash]["op_offset"][section][pre_match:pre_match + len(set_match)])), args)

                except:

                    if args.verbose == True:
                        print_asst("debug - section empty", args)

                    continue

        if run_type != "gold":
            print_asst("\t----------^ SET rule%d ^-----------" % (match_count), args)

        match_count += 1

    return

################
# Find Strings #
################

def find_string(data, args):

    data["strings"] = []
    check_strings   = []

    file = open(data["gold"], "rb").read().strip()

    # ASCII
    for string in re.finditer(rb"[ -~]{%d,}" % 4, file):

        if string.group(0) not in check_strings:

            check_strings.append(string.group(0))

    # UNICODE
    for string in re.finditer(rb"(([ -~]\x00){%d,})" % 4, file):

        if string not in check_strings:

            check_strings.append(string.group(0))

    # Check the strings to make sure they match across the samples
    for string in check_strings:

        for rule in data["yara"]:

            match_count = string_count(string, data, rule)

            if (float(match_count) / float(len(data["yara"][rule]["hashes"]))) >= args.commonality:

                data["strings"].append(string)

    return data

def string_count(string, data, rule):

    match_count = 0
    for hash in data["yara"][rule]["hashes"]:
        if re.search(re.escape(string), open(hash, "rb").read()):
            match_count += 1

    return match_count

######################
# Generate YARA Rule #
######################

def yara_disa(data, args, hashes, code_section, virt_addr, rule):

    yara_list = []
    byte_list = []
    scrape_flag = 0
    hex_count = 0

    for op in md.disasm(code_section, int(hex(virt_addr), 16) + 0x10000000):

        # Due to a Capstone bug, sometimes object won't have '_detail' which causes an infinite recursive loop and crash
        #if hasattr(op, "_detail"):
        if hasattr(op, "bytes"):

            # Start of match
            if op.address == int(data["yara"][rule]["start"], 16) or scrape_flag == 1:

                keep_bytes = ((4 - (op.prefix).count(0)) + (4 - (op.opcode).count(0))) * 2
                byte_array = "".join('{:02x}'.format(x) for x in op.bytes)
                byte_length = int(len(byte_array) / 2)
                byte_list.append(byte_array)

                # These are opcode variatons that we want to try and account for
                # A lot of time there will be varying lengths due to operands as well
                # Increase hex_count by a rough estimate of the operand lengths in bytes

                list_call = ["e8", "ff"]
                list_jmp  = ["e9", "eb"]
                list_zero = ["00"]
                list_ret  = ["c2", "c3"]
                list_mov  = ["88", "89", "8a", "8b", "8c", "8e", "a0", "a1", "a2", "a3", "a4", "a5", "c6", "c7"]
                list_push = ["50", "51", "52", "53", "54", "55", "56", "57", "6a", "ff"]
                list_pop  = ["58", "59", "5a", "5b", "5c", "5d", "5e", "5f", "07", "17", "1f", "8f"]
                list_cmp  = ["38", "39", "3a", "3b", "3c", "3d", "80", "81", "82", "83"]
                list_test = ["84", "85", "A8", "A9", "F6", "F7"]
                list_inc  = ["40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4A", "4B", "4C", "4D", "4E", "4F", "FE", "FF"]

                # CALL variations
                if op.mnemonic == "call":
                    match_count = yara_count(" ".join(yara_list) + byte_array[:2], data, rule)
                    if (float(match_count) / float(len(hashes))) >= args.commonality:
                        yara_string = "%s " % byte_array[:2] + ("?? " * (byte_length - 1)).strip()
                    else:
                        yara_string = "(E8|FF) [0-12] "
                    hex_count += 7

                # JMP variations
                elif op.mnemonic == "jmp":

                    match_count = yara_count(" ".join(yara_list) + byte_array[:2], data, rule)
                    if (float(match_count) / float(len(hashes))) >= args.commonality:
                        yara_string = "%s " % byte_array[:2] + ("?? " * (byte_length - 1)).strip()
                    else:
                        yara_string = "(E9|EB) [0-12] "
                    hex_count += 5

                # All 00's
                elif byte_array[:2] in list_zero and byte_array.count("0") == len(byte_array):

                    yara_string = ("00 " * byte_length).strip()
                    hex_count += byte_length

                # RET variations
                elif op.mnemonic == "ret":

                    match_count = yara_count(" ".join(yara_list) + byte_array[:2], data, rule)
                    if (float(match_count) / float(len(hashes))) >= args.commonality:
                        yara_string = "%s " % byte_array[:2] + ("?? " * (byte_length - 1)).strip()
                    else:
                        yara_string = "(C2|C3) [0-12] "
                    hex_count += 5

                # MOV variations
                elif op.mnemonic == "mov":

                    match_count = yara_count(" ".join(yara_list) + byte_array[:2], data, rule)
                    if (float(match_count) / float(len(hashes))) >= args.commonality:
                        yara_string = "%s " % byte_array[:2] + ("?? " * (byte_length - 1)).strip()
                    else:
                        yara_string = "(8?|A?|C?) [0-12] "
                    hex_count += 5

                # PUSH variations
                elif op.mnemonic == "push":

                    match_count = yara_count(" ".join(yara_list) + byte_array[:2], data, rule)
                    if (float(match_count) / float(len(hashes))) >= args.commonality:
                        yara_string = "%s " % byte_array[:2] + ("?? " * (byte_length - 1)).strip()
                    else:
                        yara_string = "(5?|6A|FF) [0-12]"

                    hex_count += 2

                # POP variations
                elif op.mnemonic == "pop":

                    match_count = yara_count(" ".join(yara_list) + byte_array[:2], data, rule)
                    if (float(match_count) / float(len(hashes))) >= args.commonality:
                        yara_string = "%s " % byte_array[:2] + ("?? " * (byte_length - 1)).strip()
                    else:
                        yara_string = "(5?|07|17|1F|8F) [0-12]"

                    hex_count += 2

                # INC / DEC variations
                elif op.mnemonic == "inc" or op.mnemonic == "dec":

                    match_count = yara_count(" ".join(yara_list) + byte_array[:2], data, rule)
                    if (float(match_count) / float(len(hashes))) >= args.commonality:
                        yara_string = "%s " % byte_array[:2] + ("?? " * (byte_length - 1)).strip()
                    else:
                        yara_string = "(4?|FE|FF) [0-12]"

                    hex_count += 2

                # CMP variations
                elif op.mnemonic == "cmp":

                    match_count = yara_count(" ".join(yara_list) + byte_array[:2], data, rule)
                    if (float(match_count) / float(len(hashes))) >= args.commonality:
                        yara_string = "%s " % byte_array[:2] + ("?? " * (byte_length - 1)).strip()
                    else:
                        yara_string = "(3?|8?) [0-12] "
                    hex_count += 7

                # TEST variations
                elif op.mnemonic == "test":

                    match_count = yara_count(" ".join(yara_list) + byte_array[:2], data, rule)
                    if (float(match_count) / float(len(hashes))) >= args.commonality:
                        yara_string = "%s " % byte_array[:2] + ("?? " * (byte_length - 1)).strip()
                    else:
                        yara_string = "(8?|A?|F?) [0-12] "
                    hex_count += 7

                else:

                    wildcard_byte = byte_array[0:keep_bytes] + ("?" * len(byte_array[keep_bytes:]))
                    yara_string = " ".join([wildcard_byte[i:i + 2] for i in range(0, len(wildcard_byte), 2)]).upper()
                    hex_count += byte_length

                yara_list.append(yara_string)
                scrape_flag = 1

                if args.verbose == True:
                    print_asst("debug %x | %-15s | %-15s | %2d | %-10s | %-15s | %-12s | %s" % (
                    op.address, op.prefix, op.opcode, len(op.operands), op.mnemonic, op.op_str,
                    "".join('{:02x}'.format(x) for x in op.bytes), yara_string), args)

                # Limit size of generated YARA rule so as to not go over token limits in YARA
                if op.address == int(data["yara"][rule]["end"], 16) or hex_count > 4000:

                    # Setup list for status messages
                    data["yara"][rule]["msg"] = []

                    if args.default:
                        user_answer = "Y"
                    else:
                        user_answer = user_prompt(
                            "\n    [*] Do you want to try and morph %s for accuracy and attempt to make it VT Retro friendly [Y/N] " % rule)

                    # Attempt to dynamically morph YARA rule
                    if user_answer == "Y":

                        # Due to changes in YARA there is a limit to the number of choices used when compiling
                        # Strip temporary jumps from choices and let morph add back if necessary
                        temp_list = []
                        for index, entry in enumerate(yara_list):
                            if "[" in entry:
                                temp_list.append(entry.split(" ")[0])
                                temp_list.append("??")
                            else:
                                temp_list.append(entry)
                        yara_list = temp_list

                        yara_string = yara_validate(data, hashes, yara_list, args, rule, byte_list)

                        if yara_string.startswith("FAIL"):
                            print_asst(
                                "\n\t[!] Unrecoverable errors found while morphing rule, reverting to best-guess original\n\t%s" % yara_string,
                                args)

                            data["yara"][rule]["msg"].append("Match FAILED for morphing")
                        else:
                            data["yara"][rule]["msg"].append("Match SUCCESS for morphing")

                    # Best-guess YARA rule on failure or by choice
                    if user_answer != "Y" or yara_string.startswith("FAIL"):

                        complex = False
                        count = 0

                        # This loop is intended to handle compilation issues within YARA - usually complexity related
                        while complex != True:

                            try:

                                yara_string = " ".join(yara_list[:len(yara_list) - count])
                                yara_string = yara_string.replace("(E8|FF) ", "(E8|FF) [0-12] ")
                                yara_string = yara_string.replace("(E9|EB) ", "(E9|EB) [0-12] ")
                                yara_string = yara_string.replace("(C2|C3) ", "(C2|C3) [0-12] ")
                                yara_string = yara_string.replace("(8?|A?|C?) ", "(8?|A?|C?) [0-12] ")
                                yara_string = yara_string.replace("(5?|6A|FF) ", "(5?|6A|FF) [0-12] ")
                                yara_string = yara_string.replace("(5?|07|17|1F|8F) ", "(5?|07|17|1F|8F) [0-12] ")
                                yara_string = yara_string.replace("(4?|FE|FF) ", "(4?|FE|FF) [0-12] ")
                                yara_string = yara_string.replace("(3?|8?) ", "(3?|8?) [0-12] ")
                                yara_string = yara_string.replace("(8?|A?|F?)", "(8?|A?|F?) [0-12]")

                                # Compile YARA rule
                                yara_rule = "rule test\n{\nstrings:\n$hex_string = { %s }\ncondition:\n$hex_string\n}" % yara_string
                                rules = yara.compile(source=yara_rule)

                                # Check matches
                                match_count = 0
                                for hash in data["yara"][rule]["hashes"]:
                                    if "[test]" in str(rules.match(hash)):
                                        match_count += 1

                                if (float(match_count) / float(len(hashes))) < args.commonality:
                                    count += 1
                                else:
                                    complex = True
                                    if count >= 1:
                                        print_asst("\n\t[!] Error compiling YARA rule (complexity), recovered by removing %s characters" % count, args)

                            except:
                                count += 1

                        # For 100% matches, add message
                        if (float(match_count) / float(len(hashes))) >= args.commonality:
                            data["yara"][rule]["msg"].append("Match SUCCESS for generic")
                        else:
                            data["yara"][rule]["msg"].append("Match FAILED for generic")

                    data["yara"][rule]["result"] = yara_string
                    data["yara"][rule]["bytes"] = "".join(byte_list)

                    break

        # Add raw bytes in the event it doesn't disassemble
        else:
            if scrape_flag == 1:
                byte_array = "".join('{:02x}'.format(x) for x in op.bytes)
                byte_length = int(len(byte_array) / 2)
                yara_string = ("?? " * byte_length).strip()
                hex_count += 8
                byte_list.append(byte_array)
                yara_list.append(yara_string)

    return data

def gen_peyara(data, hash, args, hashes):

    pe = pefile.PE(hash)

    for rule in data["yara"]:

        count = 0

        for section in pe.sections:

            if section.IMAGE_SCN_CNT_CODE == True or section.IMAGE_SCN_MEM_EXECUTE == True:

                code_section = pe.sections[count].get_data()[:section.SizeOfRawData]
                virt_addr    = pe.sections[count].VirtualAddress

                data = yara_disa(data, args, hashes, code_section, virt_addr, rule)

            count += 1

    return data

def gen_nonpeyara(data, hash, args, hashes):

    for rule in data["yara"]:

        data["yara"][rule]["msg"] = []

        code_section = open(data["gold"], "rb").read().strip() # Remove newline typical in shellcode copy/paste files
        virt_addr = 0x0

        data = yara_disa(data, args, hashes, code_section, virt_addr, rule)

    return data

def gen_yara(hash, data, hashes, args):

    print_asst("\n[+] Generating YARA rule for matches off of bytes from gold - %s" % hash, args)

    for rule in data["yara"]:
        data["yara"][rule]["hashes"] = list(set(data["yara"][rule]["hashes"]))

    if not args.nonpe:
        pefile.PE(hash)
        data = gen_peyara(data, hash, args, hashes)
    else:
        data = gen_nonpeyara(data, hash, args, hashes)

    return data

################################
# Dynamically Adjust YARA Rule #
################################

def yara_count(yara_string, data, rule):

    if type(yara_string) == list:
        yara_string = "".join(yara_string)

    if yara_string.startswith("FAIL"):
        return 0

    yara_rule = "rule test\n{\nstrings:\n$hex_string = { %s }\ncondition:\n$hex_string\n}" % yara_string

    try:
        rules = yara.compile(source=yara_rule)
    except:
        return -1 # ERROR - try to recover by morphing rule (too complex regex usually)

    # Check matches
    match_count = 0
    for hash in data["yara"][rule]["hashes"]:
        if "[test]" in str(rules.match(hash)):
            match_count += 1

    return match_count

def yara_straight(data, hashes, rule, yara_set, args):

    # Flip each byte until we find the one which matches across the set
    yara_string = " ".join(yara_set)

    for index, entry in enumerate(yara_set):

        if entry == "(E8|FF)": # CALL

            for byte in ["E8", "FF", "(E8|FF)"]:

                yara_set[index] = byte
                yara_string = "".join(yara_set)
                match_count = yara_count(yara_string, data, rule)
                if (float(match_count) / float(len(hashes))) >= args.commonality:
                    break

        if entry == "(E9|EB)": # JMP

            for byte in ["E9", "EB", "(E9|EB)"]:

                yara_set[index] = byte
                yara_string = "".join(yara_set)
                match_count = yara_count(yara_string, data, rule)
                if (float(match_count) / float(len(hashes))) >= args.commonality:
                    break

        if entry == "(C2|C3)": # RETN

            for byte in ["C2", "C3", "(C2|C3)"]:

                yara_set[index] = byte
                yara_string = "".join(yara_set)
                match_count = yara_count(yara_string, data, rule)
                if (float(match_count) / float(len(hashes))) >= args.commonality:
                    break


        if entry == "(8?|A?|C?)": # MOV

            for byte in ["88", "89", "8A", "8B", "8C", "8E", "A0", "A1", "A2", "A3", "A4", "A5", "C6", "C7", "(8?|A?|C?)"]:

                yara_set[index] = byte
                yara_string = "".join(yara_set)
                match_count = yara_count(yara_string, data, rule)
                if (float(match_count) / float(len(hashes))) >= args.commonality:
                    break

        if entry == "(5?|6A|FF)": # PUSH

            for byte in ["50", "51", "52", "53", "54", "55", "56", "57", "6A", "FF", "(5?|6A|FF)"]:

                yara_set[index] = byte
                yara_string = "".join(yara_set)
                match_count = yara_count(yara_string, data, rule)
                if (float(match_count) / float(len(hashes))) >= args.commonality:
                    break

        if entry == "(5?|07|17|1F|8F)": # POP

            for byte in ["58", "59", "5A", "5B", "5C", "5D", "5E", "5F", "07", "17", "1F", "8F", "(5?|07|17|1F|8F)"]:

                yara_set[index] = byte
                yara_string = "".join(yara_set)
                match_count = yara_count(yara_string, data, rule)
                if (float(match_count) / float(len(hashes))) >= args.commonality:
                    break

        if entry == "(4?|FE|FF)": # INC / DEC

            for byte in ["40", "41", "42", "43", "44", "45", "46", "47", "48", "49",
                         "4A", "4B", "4C", "4D", "4E", "4F", "FE", "FF", "(4?|FE|FF)"]:

                yara_set[index] = byte
                yara_string = "".join(yara_set)
                match_count = yara_count(yara_string, data, rule)
                if (float(match_count) / float(len(hashes))) >= args.commonality:
                    break

        if entry == "(3?|8?)": # CMP

            for byte in ["38", "39", "3A", "3B", "3C", "3D", "80", "81", "82", "83", "(3?|8?)"]:

                yara_set[index] = byte
                yara_string = "".join(yara_set)
                match_count = yara_count(yara_string, data, rule)
                if (float(match_count) / float(len(hashes))) >= args.commonality:
                    break

        if entry == "(8?|A?|F?)": # TEST

            for byte in ["84", "85", "A8", "A8", "84", "85", "(8?|A?|F?)"]:

                yara_set[index] = byte
                yara_string = "".join(yara_set)
                match_count = yara_count(yara_string, data, rule)
                if (float(match_count) / float(len(hashes))) >= args.commonality:
                    break

    return yara_string

def yara_morph(yara_set, args, data, rule, hashes):

    yara_set = [item for item in yara_set if item]

    count = len(yara_set)
    flag  = 0

    while flag == 0:

        yara_string = " ".join(yara_set[0:count])
        match_count = yara_count(yara_string, data, rule)
        if (float(match_count) / float(len(hashes))) >= args.commonality:
            flag = 1
        else:
            count -= 1

    good_match = [x for x in yara_set[0:count]]

    while good_match[count - 1] == "??":
        count -= 1

    good_match = good_match[0:count]

    continue_flag   = 1
    last_chance     = 0
    check_list      = ["(E8|FF)", "(E9|EB)", "(C2|C3)", "(8?|A?|C?)", "(5?|6A|FF)", "(4?|FE|FF)", "(5?|07|17|1F|8F)", "(3?|8?)", "(8?|A?|F?)"]

    while continue_flag == 1:

        # Iterate over every entry to insure we match on everything
        for index, entry in enumerate(yara_set[count:]):

            final_flag      = 0
            iteration_count = 0
            match           = 0
            wc_count        = 1
            first_count     = 6
            reverse_check   = 0
            flip_flag       = 0
            current_set     = ""

            # Morph the entry as needed for match
            while match != 1 and continue_flag == 1:

                iteration_count += 1

                # Morph "choice" variations
                if (good_match != [] and good_match[-1] in check_list) or flip_flag >= 1:

                    ################
                    # CALL Section #
                    ################

                    opcode_list = ["E8", "FF", "(E8|FF)"]

                    if flip_flag >= 1 and good_match[-1] in opcode_list[0:-1] and current_set == opcode_list[-1]:
                        flip_flag += 1
                        wc_count, reverse_check, first_count, entry, good_match[-1] = 0, 0, 6, entry.split(" ")[-1], opcode_list[flip_flag]
                        if flip_flag == len(opcode_list):
                            wc_count, reverse_check, first_count, entry, good_match[-1] = 0, 0, 6, entry.split(" ")[-1], opcode_list[-1]
                            final_flag = 1

                    if good_match[-1] == "(E8|FF)" and flip_flag == 0:
                        current_set = good_match[-1]
                        good_match[-1] = opcode_list[0]
                        flip_flag = 1

                    ################
                    # JMP Section #
                    ################

                    opcode_list = ["E9", "EB", "(E9|EB)"]

                    if flip_flag >= 1 and good_match[-1] in opcode_list[0:-1] and current_set == opcode_list[-1]:
                        flip_flag += 1
                        wc_count, reverse_check, first_count, entry, good_match[-1] = 0, 0, 6, entry.split(" ")[-1], opcode_list[flip_flag]
                        if flip_flag == len(opcode_list):
                            wc_count, reverse_check, first_count, entry, good_match[-1] = 0, 0, 6, entry.split(" ")[-1], opcode_list[-1]
                            final_flag = 1

                    if good_match[-1] == "(E9|EB)" and flip_flag == 0:
                        current_set = good_match[-1]
                        good_match[-1] = opcode_list[0]
                        flip_flag = 1

                    ################
                    # RETN Section #
                    ################

                    opcode_list = ["C2", "C3", "(C2|C3)"]

                    if flip_flag >= 1 and good_match[-1] in opcode_list[0:-1] and current_set == opcode_list[-1]:
                        flip_flag += 1
                        wc_count, reverse_check, first_count, entry, good_match[-1] = 0, 0, 6, entry.split(" ")[-1], opcode_list[flip_flag]
                        if flip_flag == len(opcode_list):
                            wc_count, reverse_check, first_count, entry, good_match[-1] = 0, 0, 6, entry.split(" ")[-1], opcode_list[-1]
                            final_flag = 1

                    if good_match[-1] == "(C2|C3)" and flip_flag == 0:
                        current_set = good_match[-1]
                        good_match[-1] = opcode_list[0]
                        flip_flag = 1

                    ###############
                    # MOV Section #
                    ###############

                    opcode_list = ["88", "89", "8A", "8B", "8C", "8E", "A0", "A1", "A2", "A3", "A4", "A5", "C6", "C7", "(8?|A?|C?)"]

                    if flip_flag >= 1 and good_match[-1] in opcode_list[0:-1] and current_set == opcode_list[-1]:
                        flip_flag += 1
                        wc_count, reverse_check, first_count, entry, good_match[-1] = 0, 0, 6, entry.split(" ")[-1], opcode_list[flip_flag]
                        if flip_flag == len(opcode_list):
                            wc_count, reverse_check, first_count, entry, good_match[-1] = 0, 0, 6, entry.split(" ")[-1], opcode_list[-1]
                            final_flag = 1

                    if good_match[-1] == "(8?|A?|C?)" and flip_flag == 0:
                        current_set = good_match[-1]
                        good_match[-1] = opcode_list[0]
                        flip_flag = 1

                    ################
                    # PUSH Section #
                    ################

                    opcode_list = ["50", "51", "52", "53", "54", "55", "56", "57", "6A", "FF", "(5?|6A|FF)"]

                    if flip_flag >= 1 and good_match[-1] in opcode_list[0:-1] and current_set == opcode_list[-1]:
                        flip_flag += 1
                        wc_count, reverse_check, first_count, entry, good_match[-1] = 0, 0, 6, entry.split(" ")[-1], opcode_list[flip_flag]
                        if flip_flag == len(opcode_list):
                            wc_count, reverse_check, first_count, entry, good_match[-1] = 0, 0, 6, entry.split(" ")[-1], opcode_list[-1]
                            final_flag = 1

                    if good_match[-1] == "(8?|A?|C?)" and flip_flag == 0:
                        current_set = good_match[-1]
                        good_match[-1] = opcode_list[0]
                        flip_flag = 1

                    ###############
                    # POP Section #
                    ###############

                    opcode_list = ["58", "59", "5A", "5B", "5C", "5D", "5E", "5F", "07", "17", "1F", "8F", "(5?|07|17|1F|8F)"]

                    if flip_flag >= 1 and good_match[-1] in opcode_list[0:-1] and current_set == opcode_list[-1]:
                        flip_flag += 1
                        wc_count, reverse_check, first_count, entry, good_match[-1] = 0, 0, 6, entry.split(" ")[-1], opcode_list[flip_flag]
                        if flip_flag == len(opcode_list):
                            wc_count, reverse_check, first_count, entry, good_match[-1] = 0, 0, 6, entry.split(" ")[-1], opcode_list[-1]
                            final_flag = 1

                    if good_match[-1] == "(5?|07|17|1F|8F)" and flip_flag == 0:
                        current_set = good_match[-1]
                        good_match[-1] = opcode_list[0]
                        flip_flag = 1

                    #####################
                    # INC / DEC Section #
                    #####################

                    opcode_list = ["40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4A", "4B", "4C", "4D", "4E", "4F", "FE", "FF", "(4?|FE|FF)"]

                    if flip_flag >= 1 and good_match[-1] in opcode_list[0:-1] and current_set == opcode_list[-1]:
                        flip_flag += 1
                        wc_count, reverse_check, first_count, entry, good_match[-1] = 0, 0, 6, entry.split(" ")[-1], opcode_list[flip_flag]
                        if flip_flag == len(opcode_list):
                            wc_count, reverse_check, first_count, entry, good_match[-1] = 0, 0, 6, entry.split(" ")[-1], opcode_list[-1]
                            final_flag = 1

                    if good_match[-1] == "(4?|FE|FF)" and flip_flag == 0:
                        current_set = good_match[-1]
                        good_match[-1] = opcode_list[0]
                        flip_flag = 1

                    ###############
                    # CMP Section #
                    ###############

                    opcode_list = ["38", "39", "3A", "3B", "3C", "3D", "80", "81", "82", "83", "(3?|8?)"]

                    if flip_flag >= 1 and good_match[-1] in opcode_list[0:-1] and current_set == opcode_list[-1]:
                        flip_flag += 1
                        wc_count, reverse_check, first_count, entry, good_match[-1] = 0, 0, 6, entry.split(" ")[-1], opcode_list[flip_flag]
                        if flip_flag == len(opcode_list):
                            wc_count, reverse_check, first_count, entry, good_match[-1] = 0, 0, 6, entry.split(" ")[-1], opcode_list[-1]
                            final_flag = 1

                    if good_match[-1] == "(3?|8?)" and flip_flag == 0:
                        current_set = good_match[-1]
                        good_match[-1] = opcode_list[0]
                        flip_flag = 1

                    ################
                    # TEST Section #
                    ################

                    opcode_list = ["84", "85", "A8", "A9", "F6", "F7", "(8?|A?|F?)"]

                    if flip_flag >= 1 and good_match[-1] in opcode_list[0:-1] and current_set == opcode_list[-1]:
                        flip_flag += 1
                        wc_count, reverse_check, first_count, entry, good_match[-1] = 0, 0, 6, entry.split(" ")[-1], opcode_list[flip_flag]
                        if flip_flag == len(opcode_list):
                            wc_count, reverse_check, first_count, entry, good_match[-1] = 0, 0, 6, entry.split(" ")[-1], opcode_list[-1]
                            final_flag = 1

                    if good_match[-1] == "(8?|A?|F?)" and flip_flag == 0:
                        current_set = good_match[-1]
                        good_match[-1] = opcode_list[0]
                        flip_flag = 1

                # Compile YARA rule
                yara_string = " ".join(good_match) + " " + entry

                if args.verbose == True:
                    print_asst("\n\tdebug !!! +5 -5\n%s" % yara_set[count + index - 5:index + 6], args)
                    print_asst("\n\tdebug !!! yara %d %s\n%s" % (count + index, entry, yara_string), args)

                # For 100% matches, add and move on
                match_count = yara_count(yara_string, data, rule)
                if (float(match_count) / float(len(hashes))) >= args.commonality:

                    for value in entry.split(" "):
                        good_match.append(value)

                    match = 1

                # For failures, iterate over a number of possibilities to to adjust the rule
                else:

                    if args.verbose == True:
                        print_asst("\n\tdebug pre - final %d last %d rev %d flip %d entry %s" % (final_flag, last_chance, reverse_check, flip_flag, entry), args)

                    # If we've failed after our hail mary, go ahead and exit - most likely unaccounted for opcode variation
                    if good_match[-1] == "[0-12]":

                        yara_string     = "FAIL: Index - %d | Entry - %s | List - %s" % (count + index, entry, yara_set[count + index - 5:count + index + 6])
                        continue_flag   = 0

                    # If over 250 iterations on the same entry, we have a problem and may fail
                    # This may need to be adjusted but about 14 variants PER opcode
                    # EG: mnemonic with 10 variants would be 140 iterations if it went to the end
                    if iteration_count > 250:

                        # Clean up wildcards until two bytes are touching
                        if good_match[-1] == "??":

                            del good_match[-1]

                        # Hail mary large jump between 2 bytes - could lead to bad matches, but they will subsequently end back up here and fail
                        elif good_match[-1] != "??" and good_match[-1] != "[0-12]":

                            entry = entry.split(" ")[-1]
                            good_match.append("[0-12]")

                        # Unable to proceed - most likely an unaccounted for opcode variation
                        else:

                            yara_string     = "FAIL: Index - %d | Entry - %s | List - %s" % (count + index, entry, yara_set[count + index - 5:count + index + 6])
                            continue_flag   = 0

                            break

                    # Dynamically adjust distant between two bytes with hard wildcards, then increasing ranges
                    if wc_count >= 6:

                        # If all else hasn't matched, try to reverse the hex jump
                        if first_count == 0 and reverse_check == 0:

                            entry           = "[%d-12] %s" % (wc_count, entry.split(" ")[-1])
                            reverse_check   = 1

                        # Try to increase the jump range on each iteration until it bottoms out
                        if first_count > 0 and reverse_check == 0:

                            first_count -= 1
                            entry       = "[%d-%d] %s" % (first_count, wc_count, entry.split(" ")[-1])

                    # Hard set wildcards
                    else:

                        # Clean up wildcards until two bytes are touching
                        if good_match[-1] == "??":

                            del good_match[-1]

                        else:

                            entry       = "??" + " " + entry
                            wc_count    += 1

                    if args.verbose == True:
                        print_asst("\n\tdebug post - final %d last %d rev %d flip %d entry %s" % (final_flag, last_chance, reverse_check, flip_flag, entry), args)

        continue_flag = 0

    return yara_string.replace(" ","")

def yara_validate(data, hashes, yara_list, args, rule, byte_list):

    yara_set = (" ".join(yara_list)).split(" ") # Splits instructions on a byte basis

    # Only try the first two matches if opcode technique not forced
    if not args.opcode:

        #
        # Match criteria 01 - Exact byte match including operands
        #
        print_asst("\n[+] Check 01 - Checking for exact byte match", args)

        yara_string = "".join(byte_list)

        match_count = yara_count(yara_string, data, rule)
        if (float(match_count) / float(len(hashes))) >= args.commonality:

            print_asst("\t[*] Exact byte match found across all samples", args)

            return yara_string

        #
        # Match criteria 02 - Flip opcodes to exact byte if operand length remains the same
        #
        print_asst("\n[+] Check 02 - Checking for optimal opcode match", args)

        yara_string = " ".join(yara_set)

        # Validate our generic match hits all samples
        # This will show that there is no variation in operand length between samples
        match_count = yara_count(yara_string, data, rule)
        if (float(match_count) / float(len(hashes))) >= args.commonality:

            yara_string = yara_straight(data, hashes, rule, yara_set, args)

        match_count = yara_count(yara_string, data, rule)
        if (float(match_count) / float(len(hashes))) >= args.commonality:

            print_asst("\t[*] Found optimal opcode match across all samples", args)

            return yara_string

    #
    # Match criteria 03 - Dynamically morph YARA by adjusting length/opcode, more error prone
    #
    print_asst("\n[+] Check 03 - Dynamically morphing YARA %s" % rule, args)

    yara_string = yara_morph(yara_set, args, data, rule, hashes)

    match_count = yara_count(yara_string, data, rule)
    if (float(match_count) / float(len(hashes))) >= args.commonality:

        print_asst("\t[*] Dynamic morphing succeeded", args)

        return yara_string

    return yara_string

###################
# Print YARA Rule #
###################

def print_yara(data, args):

    comment_flag    = 0
    byte_flag       = 0

    if args.default:
        user_answer = "Y"
    else:
        user_answer = user_prompt("\n    [*] Do you want to include matched sample names in rule meta? [Y/N] ")

    if user_answer == "Y":
        comment_flag = 1

    if args.default:
        user_answer = "Y"
    else:
        user_answer = user_prompt("\n    [*] Do you want to include matched byte sequence in rule comments? [Y/N] ")

    if user_answer == "Y":
        byte_flag = 1

    print_asst("\n[+] Completed YARA rules", args)

    for rule in data["yara"]:

        print("\n/*")

        if comment_flag == 1:
            print("""\nSAMPLES:

%s""" % "\n".join(data["yara"][rule]["hashes"]))

        if byte_flag == 1:
            print("""\nBYTES:

%s""" % data["yara"][rule]["bytes"].upper())

        print("""
INFO:

%s
%s

*/

rule %s
    {
        meta:
            description = "Autogenerated by Binsequencer v.%s from %s"
            author      = ""
            date        = "%s"

        strings:
            $%s_bytes = { %s }
""" % (" ".join(sys.argv[0:]),
        "\n".join(data["yara"][rule]["msg"]),
        rule,
        __version__,
        data["gold"],
        time.strftime("%Y-%m-%d"),
        rule,
        data["yara"][rule]["result"].replace(" ","").upper()))

        if args.strings:

            for count, string in enumerate(data["strings"]):

                print("%s$string_%s = { %s } // %s" % (" " * 12,
                                                        count,
                                                        "".join([hex(ord(x))[2:] for x in string]).upper(),
                                                        string))
            print("")

        print("""%scondition:
            all of them
}\n""" % (" " * 8))

    return

def main():

    parser = argparse.ArgumentParser(description="Sequence a set of binaries to identify commonalities in code structure.")

    parser.add_argument("-c", "--commonality", help="Commonality percentage the sets criteria for matches, default 100", metavar="<integer_percent>", type=int, default=100)
    parser.add_argument("-m", "--matches", help="Set the minimum number of matches to find, default 1", metavar="<integer>", type=int, default=1)
    parser.add_argument("-l", "--length", help="Set the minimum length of the instruction set, default 25", metavar="<integer>", type=int, default=25)
    parser.add_argument("-v", "--verbose", help="Prints data while processing, use only for debugging", action="store_true")
    parser.add_argument("-a", "--arch", help="Select code architecture of samples, default x86", choices=["x86", "x64"], default="x86")
    parser.add_argument("-g", "--gold", help="Override gold selection", metavar="<file>")
    parser.add_argument("-d", "--default", help="Accept default prompt values", action="store_true")
    parser.add_argument("-Q", "--quiet", help="Disable output except for YARA rule", action="store_true")
    parser.add_argument("-n", "--nonpe", help="Process non-PE files (eg PCAP/JAR/PDF/DOC)", action="store_true")
    parser.add_argument("-o", "--opcode", help="Use only the opcode matching technique", action="store_true")
    parser.add_argument("-s", "--strings", help="Include strings in YARA for matched hashes", action="store_true")
    parser.add_argument("file", nargs=argparse.REMAINDER)

    args                = parser.parse_args()
    args.commonality    = float(args.commonality) / float(100) # Determine how many hashes need to match
    hashes              = []
    data                = {
        "matches"   : {},
        "sets"      : {"longest": {}},
        "yara"      : {},
        "blacklist" : [],
        "keeplist"  : {}
    }

    if not args.file:
        print_asst("[!] Please specify a file (-f) that includes path to sample or a directory", args)
        sys.exit(1)

    ####################
    # Capstone Options #
    ####################
    global md
    if args.arch == "x86":
        md = Cs(CS_ARCH_X86, CS_MODE_32)  # x86
    elif args.arch == "x64":
        md = Cs(CS_ARCH_X86, CS_MODE_64)  # x64
    md.skipdata = True  # Skip data
    md.detail = True  # Show details

    print_asst("\n[+] Extracting instructions and generating sets\n", args)

    # Check if individual file or directory
    if os.path.isfile(args.file[0]):

        data = process_files(args.file[0], data, args)
        hashes.append(args.file[0])

    # Open directory of files
    else:

        for hash in [os.path.join(args.file[0], fn) for fn in next(os.walk(args.file[0]))[2]]:

            try:
                data = process_files(hash.strip(), data, args)
            except:
                pass

            if hash in data:
                hashes.append(hash.strip())

    # Find golden hash
    data = find_gold(hashes, data, args)

    # Find longest matched opcode blob size
    longest_match(hashes, data, args)

    # Find offset of match across all hashes
    print_offset(data, args)

    # Find strings
    find_string(data,args)

    # Generate YARA_rule
    data = gen_yara(data["gold"], data, hashes, args)

    # Print YARA rule
    print_yara(data, args)

if __name__ == '__main__':
    main()