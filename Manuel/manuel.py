''' 
  This script was massively, massively different and over the top until I read https://h0mbre.github.io/LTER_SEH_Success/ by @h0mbre_
  I was also pointed towards https://github.com/ihack4falafel/Slink by @ihack4falafel

  A big thank you to both of them for writing up and posting their work so skids like me can learn from them <3 
'''

import sys
import time
import argparse
import random

debug = False
output_format = ""
encoded_shellcode = ""
bad_chars = ["00", "01", "10", "11", "f"]

# output vars
default_delim = " => "
python_comment = " # "
python_output = []

# hardcoded opcode/instructions
and_eax_p1 = "\\x25\\x4a\\x4d\\x4e\\x55"            # and eax, 0x554e4d4a
and_eax_p2 = "\\x25\\x35\\x32\\x31\\x2a"            # and eax, 0x2a313235
and_eax_p1_description = "and eax, 0x554e4d4a"
and_eax_p2_description = "and eax, 0x2a313235"
add_op = "\\x05"
add_eax_description = "add eax, 0x"
push_eax = "\\x50"                      # push eax
push_eax_description = "push eax"
sub_eax = "\\x2d\\x33\\x33\\x33\\x33"           # sub eax, 0x33333333   - we can probably randomise this
sub_eax_description = "sub eax, 0x33333333"

    
def has_bad_chars(bytes, bad_bytes):
    two_bytes = [bytes[i:i+2] for i in range(0, len(bytes), 2)]
    has_bad = False 
    
    # check all but the f char (don't like this code, don't look)
    for bb in bad_bytes:
        if len(bb) == 2:
            if any(i == bb for i in list(two_bytes)):
                has_bad = True
        else:
            if any(i == bb for i in list(bytes)):
                has_bad = True
    return has_bad

'''
 the encoder() performs all the magic
 seperate_adds can = 2 or 3, depending on whether the shellcode chunks contain bad chars or not
 the logic of the encoder is relatively simple:
 
 if seperate_adds is 2 and we want a 4: we can have 2 and 2
 if seperate_adds is 2 and we want a 5: we can do 3 and 2
 if seperate_adds is 3 and we want a 0: we can do 1 and 1 and 1 minus the 3
 if seperate_adds is 3 and we want an a (10): we can do 5 + 4 + 4 minus the 3

 Note: This function is pretty heavy and could be broken down and cleaned up pretty easily, but it works. 
'''
def encode(item, seperate_adds):
    global encoded_shellcode, debug, output_format
    all_chars = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"]
    adds = []
    
    if seperate_adds == 3:
        adds = ["","",""]
    else:
        adds = ["",""]

    for i in list(item):
        if i in all_chars:
            # value should be the target value we need to count up to
            val = all_chars.index(i)
            add_one = ""
            add_two = ""
            add_three = ""
            
            if seperate_adds == 2:
                # are we even?      
                if val % 2 == 0:
                    half = int(val / 2)
                    add_one = half
                    add_two = half
                else:
                    temp = val - 1
                    half = int(temp / 2)
                    add_one = half + 1
                    add_two = half
                    
                adds[0] += str(add_one)
                adds[1] += str(add_two)
            else:
                sub_value = 3
                val += sub_value # account for the sub at the end
                # are we divisble by 3
                remainder = val % 3

                if remainder == 0:
                    third = int(val / 3)
                    add_one = third
                    add_two = third
                    add_three = third
                elif remainder == 1:
                    temp = val - remainder
                    third = int(temp / 3)
                    add_one = third + 1
                    add_two = third
                    add_three = third
                else:
                    temp = val - remainder
                    third = int(temp / 3)
                    add_one = third + 1
                    add_two = third + 1
                    add_three = third

                adds[0] += str(add_one)
                adds[1] += str(add_two)
                adds[2] += str(add_three)

    # following should probably be in a seperate functions to handle their tings, but meh. It works.
    if seperate_adds == 2:
        first_add = adds[0]
        second_add = adds[1]

        first_add  = [first_add[i:i+2] for i in range(0, len(first_add), 2)]
        second_add = [second_add[i:i+2] for i in range(0, len(second_add), 2)]

        first_add_shellcode = add_op + "\\x" + first_add[3] + "\\x" + first_add[2] + "\\x" + first_add[1] + "\\x" + first_add[0]
        second_add_shellcode = add_op + "\\x" + second_add[3] + "\\x" + second_add[2] + "\\x" + second_add[1] + "\\x" + second_add[0]

        # adding our current encoded shellcode to our overall shellcode
        encoded_shellcode += and_eax_p1
        encoded_shellcode += and_eax_p2
        encoded_shellcode += first_add_shellcode
        encoded_shellcode += second_add_shellcode
        encoded_shellcode += push_eax

        if debug:
            print("")
            print(and_eax_p1 + default_delim + and_eax_p1_description)
            print(and_eax_p2 + default_delim + and_eax_p2_description)
            print(first_add_shellcode + default_delim + add_eax_description + first_add[0] + first_add[1] + first_add[2] + first_add[3])
            print(second_add_shellcode + default_delim + add_eax_description + second_add[0] + second_add[1] + second_add[2] + second_add[3])
            print(push_eax + default_delim + push_eax_description)
            print("")

        if output_format == "py":
            python_var = "enc += "
            python_output.append(python_var + "\"" + and_eax_p1 + "\"" + python_comment + and_eax_p1_description)
            python_output.append(python_var + "\"" + and_eax_p2 + "\"" + python_comment + and_eax_p2_description)
            python_output.append(python_var + "\"" + first_add_shellcode + "\"" + python_comment + add_eax_description + first_add[0] + first_add[1] + first_add[2] + first_add[3])
            python_output.append(python_var + "\"" + second_add_shellcode + "\"" + python_comment + add_eax_description + second_add[0] + second_add[1] + second_add[2] + second_add[3])
            python_output.append(python_var + "\"" + push_eax + "\"" + python_comment + push_eax_description)
            python_output.append("")

    else:
        first_add = adds[0]
        second_add = adds[1]
        third_add = adds[2]

        first_add  = [first_add[i:i+2] for i in range(0, len(first_add), 2)]
        second_add = [second_add[i:i+2] for i in range(0, len(second_add), 2)]
        third_add = [third_add[i:i+2] for i in range(0, len(third_add), 2)]

        first_add_shellcode = add_op + "\\x" + first_add[3] + "\\x" + first_add[2] + "\\x" + first_add[1] + "\\x" + first_add[0]
        second_add_shellcode = add_op + "\\x" + second_add[3] + "\\x" + second_add[2] + "\\x" + second_add[1] + "\\x" + second_add[0]
        third_add_shellcode = add_op + "\\x" + third_add[3] + "\\x" + third_add[2] + "\\x" + third_add[1] + "\\x" + third_add[0]

        # adding our current encoded shellcode to our overall shellcode
        encoded_shellcode += and_eax_p1
        encoded_shellcode += and_eax_p2
        encoded_shellcode += first_add_shellcode
        encoded_shellcode += second_add_shellcode
        encoded_shellcode += third_add_shellcode
        encoded_shellcode += sub_eax
        encoded_shellcode += push_eax

        if debug:
            print("")
            print(and_eax_p1 + default_delim + and_eax_p1_description)
            print(and_eax_p2 + default_delim + and_eax_p2_description)
            print(first_add_shellcode + default_delim + add_eax_description + first_add[0] + first_add[1] + first_add[2] + first_add[3])
            print(second_add_shellcode + default_delim + add_eax_description + second_add[0] + second_add[1] + second_add[2] + second_add[3])
            print(third_add_shellcode + default_delim + add_eax_description + third_add[0] + third_add[1] + third_add[2] + third_add[3])
            print(sub_eax + default_delim + sub_eax_description)    
            print(push_eax + default_delim + push_eax_description)
            print("")

        if output_format == "py":
            python_var = "enc += "
            python_output.append(python_var + "\"" + and_eax_p1 + "\"" + python_comment + and_eax_p1_description)
            python_output.append(python_var + "\"" + and_eax_p2 + "\"" + python_comment + and_eax_p2_description)
            python_output.append(python_var + "\"" + first_add_shellcode + "\"" + python_comment + add_eax_description + first_add[0] + first_add[1] + first_add[2] + first_add[3])
            python_output.append(python_var + "\"" + second_add_shellcode + "\"" + python_comment + add_eax_description + second_add[0] + second_add[1] + second_add[2] + second_add[3])
            python_output.append(python_var + "\"" + third_add_shellcode + "\"" + python_comment + add_eax_description + third_add[0] + third_add[1] + third_add[2] + third_add[3])
            python_output.append(python_var + "\"" + sub_eax + "\"" + python_comment + sub_eax_description) 
            python_output.append(python_var + "\"" + push_eax + "\"" + python_comment + push_eax_description)
            python_output.append("")

def main():
    global debug, output_format
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true", help="Print debug information at runtime")
    parser.add_argument("-s", "--shellcode", type=str, help="Raw shellcode to encode (wrap in \" \")")
    parser.add_argument("-sf", "--shellfile", type=str, help="Path to file holding raw shellcode")
    parser.add_argument("-f", "--format", type=str, help="Format: py = python")
    args = parser.parse_args()

    # handle cmdline arguments
    debug = args.debug

    if args.format:
        output_format = args.format
        if output_format != "py":
            print("Unknown output format specified, ignoring")
            output_format = ""

    print("")
    print("Manuel is here to help you encode your shellcode to bypass those pesky bad chars")
    print("Let's begin...")

    # take shellcode as raw input
    if args.shellcode:
        shellcode = args.shellcode
    elif args.shellfile:
        # open the shellcode file
        with open(args.shellfile) as f:
            shellcode = f.read()
            shellcode = shellcode.replace("\n", "")
            shellcode = shellcode.replace("\r", "")     
    else:
        shellcode = input("Enter your raw shellcode: ").lower()
        print("")
        
    shellcode = shellcode.replace("\\x", "")
    shellcode = shellcode.replace("'", "")
    shellcode = shellcode.replace("\"", "")

    nop_op = "90"

    # if we have less shellcode than the minimum required (4), then we get mod issues.
    shellcode_size = int(len(shellcode) / 2)
    temp = [shellcode[i:i+2] for i in range(0, len(shellcode), 2)]
    shellcode_size = len(temp)

    if shellcode_size < 4:
        difference = 4 - shellcode_size
        print("[!] Shellcode is less than 4 bytes, padding with %d NOPS" % difference)
        for i in range(0, difference):
            shellcode += nop_op
        # recalculate now; we should be atleast 4
        shellcode_size = int(len(shellcode) / 2)

    # check the size of user provided shellcode and pad with NOPS if need be
    mod4_remainder = int(shellcode_size % 4)
    mod4_remainder = 4 - mod4_remainder

    if mod4_remainder != 0 and mod4_remainder != 4:
        print("[!] Shellcode is not divisible by 4")
        print("[+] Padding shellcode with %d NOPS.." % mod4_remainder)
        for i in range(0, mod4_remainder):
            shellcode += "90"

    shellcode = "".join(reversed([shellcode[i:i+2] for i in range(0, len(shellcode), 2)]))
    shellcode_formatted = ""
    shellcode_formatted = [shellcode[i:i+8] for i in range(0, len(shellcode), 8)]

    print("")

    enc_counter = 1
    for sc in shellcode_formatted:
        print("[*] Encoding chunk: %d -> %s" % (enc_counter, sc))
        time.sleep(0.25)
        
        # if this is true go to alternative encoder - utilising three hex values
        #if any(i == "00" for i in list(two_bytes)) or any(i == "01" for i in list(two_bytes)) or any(i == "10" for i in list(two_bytes)) or any(i == "11" for i in list(two_bytes)) or any(i == "f" for i in list(item)):
        if has_bad_chars(sc, bad_chars):
            time.sleep(0.25)
            if debug: print("[!] Possible bad character found, using \"add, add, add, sub\" encoder")
            encode(sc, 3)
        # if this is true, use the default encoder - utilising two seperate hex values
        else:
            time.sleep(0.25)
            if debug: print("[+] No bad characters found, using \"add, add\" encoder")
            encode(sc, 2)
        
        enc_counter += 1

    # we can calculate the final size by taking the whole shellcode and divide by 2 (removes the \x per byte)
    # then divide by 2 again because there are 2 values (chars) per 'byte' - total divide by 4
    shellcode_final_size = int(len(encoded_shellcode) / 4)

    time.sleep(0.5)
    print("")
    print("[*] Generating final shellcode")
    time.sleep(0.5)
    
    print("[*] Shellcode final size: " + str(shellcode_final_size) + " bytes")
    print("")
    print(encoded_shellcode)

    if output_format == "py":
        print("")
        print("---------------------------------------")
        print("Python format:")
        for l in python_output:
            print(l)

if __name__ == '__main__':
    main()
