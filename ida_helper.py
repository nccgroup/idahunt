#
# Wrappers on some IDA Python functions to help using them :)
#
# It has been heavily tested on x86/x86_64 but could possibly be modified to
# work on other architectures.
#

from idc import *
from idautils import *
import idaapi
import sark
import binascii
import sys
import ida_segment
import idautils
import idaapi
import ida_name

def logmsg(s, end=None):
    if type(s) == str:
        if end != None:
            print("[ida_helper] " + s, end=end)
        else:
            print("[ida_helper] " + s)
    else:
        print(s)

# Attempt to have globals we can use in all other functions without having to
# worry about architecture :)
info = idaapi.get_inf_structure()
if info.is_64bit():
    ERROR_MINUS_1 = 0xffffffffffffffff
    SIZE_POINTER = 8
    ARCHITECTURE = 64
    Pword = get_qword
else:
    ERROR_MINUS_1 = 0xffffffff
    SIZE_POINTER = 4
    ARCHITECTURE = 32
    Pword = get_wide_dword

# Gives us the xrefs jumping/calling an address
def get_xrefs(ea = get_screen_ea()):
    res = []
    for e in XrefsTo(ea):
        #logmsg("0x%x -> 0x%x" % (e.frm, e.to))
        res.append(e.frm)
    return res

# Gives the current function's name an address is part of
def get_function_name(ea = get_screen_ea()):
    func = idaapi.get_func(ea)
    funcname = get_func_name(func.start_ea)
    #logmsg("%X is in %s" % (ea, funcname))
    return funcname

# Gives the current function's address an address is part of
def get_function_addr(ea = get_screen_ea()):
    func = idaapi.get_func(ea)
    if not func:
        logmsg("Error: get_function_addr: Failed to find function start for 0x%x" % ea)
        return None
    return func.start_ea

# Renames an address with a name (and append a digit at the end if already
# exists)
def rename_function(e, funcname):
    currname = funcname
    count = 1
    if e == None:
        logmsg("Error: can't rename Nonetype to %s" % funcname)
        return False
    while not set_name(e, currname, SN_CHECK):
        currname = "%s_%d" % (funcname, count)
        count += 1
        if count > 100:
            logmsg("Error: rename_function looped too much for 0x%d -> %s" % (e, funcname))
            return False
    return True

# Remove name for a function (most likely to have sub_XXXXXXXX back after that)
def unname_address(e):
    if not set_name(e, "", SN_CHECK):
        logmsg("Error: unname_address: could not remove name for element")
        return False
    return True
unname_function = unname_address

# Retrieve a list with all the idbs' segments' names
def get_segments():
    seg_names = []
    for seg in idautils.Segments():
        st = ida_segment.getseg(seg)
        seg_names.append(idaapi.get_segm_name(st))
    return seg_names

# Note this must match the list of segments in the current file
default_seg_names = [".init", ".plt", ".text", ".fini", ".rodata", ".eh_frame_hdr",
             "eh_frame", ".gcc_except_table", ".tdata", ".ctors", ".dtors",
             ".jcr", ".got", ".got.plt", ".data", "freq_data_section",
             ".bss", "extern", "abs", ".rdata"]
# For each segment name, save start address, end address in a dictionary
# This can be used to know if a pointer in one segment is part of another
# segment
def get_segments_info(seg_names=default_seg_names):
    res = {}
    for name in seg_names:
        seg = idaapi.get_segm_by_name(name)
        if not seg:
            continue
        res[name] = {}
        res[name]['start_ea'] = seg.start_ea
    for n in range(idaapi.get_segm_qty()):
        seg = idaapi.getnseg(n)
        for name,d in res.items():
            if d['start_ea'] == seg.start_ea:
                res[name]['ID'] = seg.name # this is an ID, not a name, kthx IDA :(
                res[name]['end_ea'] = seg.end_ea
    return res

# Checks if an address is part of a given segment
# seg_info = get_segments_info() is passed to this function
def addr_is_in_one_segment(addr, seg_info):
    for name, d in seg_info.items():
        if addr <= seg_info[name]["end_ea"] and addr >= seg_info[name]["start_ea"]:
            return True
    return False

def name_to_rva(s):
    addr = get_name_ea_simple(s)
    if addr == ERROR_MINUS_1:
        logmsg("Error: name_to_rva: Failed to find '%s' symbol" % s)
        return None
    logmsg("image base 0x%x" % idaapi.get_imagebase())
    return addr - idaapi.get_imagebase()

# Returns the address of any name: function, label, global, etc.
def name_to_addr(s):
    addr = get_name_ea_simple(s)
    if addr == ERROR_MINUS_1:
        logmsg("Error: name_to_addr: Failed to find '%s' symbol" % s)
        return None
    return addr

def addr_to_name(ea):
    name = get_name(ea, ida_name.GN_VISIBLE)
    if name == "":
        logmsg("Error: addr_to_name: Failed to find '0x%x' address" % ea)
        return ""
    return name

# Gives the first Xref
def first_xref(addr):
    for e in XrefsTo(addr):
        addr = e.frm
        return addr
    logmsg("Error: first_xref: Failed to find xref for 0x%x" % addr)
    return None

# Gives the first Xref of first Xref to an address
def first_xref_of_first_xref(addr):
    for e in XrefsTo(addr):
        addr = e.frm
        for e in XrefsTo(addr):
            addr = e.frm
            return addr
    logmsg("Error: first_xref_of_first_xref: Failed to find xref for 0x%x" % addr)
    return None

# Gives the second Xref
def second_xref(addr):
    i = 1
    for e in XrefsTo(addr):
        frm = e.frm
        if i == 2:
            return frm
        i += 1
    logmsg("Error: second_xref: Failed to find xref for 0x%x" % addr)
    return None

# Gives the third Xref
def third_xref(addr):
    i = 1
    for e in XrefsTo(addr):
        frm = e.frm
        if i == 3:
            return frm
        i += 1
    logmsg("Error: third_xref: Failed to find xref for 0x%x" % addr)
    return None

# Gives the last Xref
def last_xref(addr):
    frm = None
    for e in XrefsTo(addr):
        frm = e.frm
        #print("0x%x" % frm)
    if frm == None:
        logmsg("Error: last_xref: Failed to find xref for 0x%x" % addr)
    return frm

# Rename a function
def rename_address(e, funcname):
    if not set_name(e, funcname, SN_CHECK):
        logmsg("Error: rename_address: Impossible to rename 0x%x with %s" % (e, funcname))
        return None
    return "OK"

# Find a series of bytes
# e.g. with byteStr = JMP_ESP = '\xff\xe4'
def find_gadget(byteStr):
    seg_info = get_segments_info()
    addr = seg_info[".text"]["start_ea"]
    while addr <= seg_info[".text"]["end_ea"]:
        b = get_bytes(addr, len(byteStr))
        if b == byteStr:
            #logmsg("Found candidate for gadget %s in .text at 0x%x" % (binascii.hexlify(byteStr), addr))
            return addr
        addr += 1
    if addr > seg_info[".data"]["end_ea"]:
        logmsg("Error: Could not find gadget in .text")
        return None

# helper for get_call_arguments()-like for when we get a register instead of a useful
# value as an argument, so we can retrieve what the register value is.
# e.g.
# .text:08380F8D   mov     eax, offset aAdmin_quick_ha ; "admin_quick_handoff"
# .text:08380F92   mov     [esp+20h], edi
# .text:08380F96   mov     [esp+1Ch], ecx
# .text:08380F9A   mov     [esp+18h], edx
# .text:08380F9E   mov     [esp+4], eax
# .text:08380FA2   mov     dword ptr [esp], offset aUnicorn_admi_0 ; "unicorn_admin_server.c"
# .text:08380FA9   call    unicorn_log_impl
# assuming we are on instruction at 08380F9E, we want to resolve what eax is i.e. 0x0921BA08
# .rodata:0921BA08 aAdmin_quick_ha db 'admin_quick_handoff',0
def get_register_value(e=get_screen_ea(), register=None, count_max=20):

    reg = print_operand(e, 1)
    if register != reg:
        logmsg("Error: bad register at 0x%x" % e)
        return None

    arg_instructions = ["mov     %s",
                        "movsxd  %s",
                        "lea     %s"]

    e = prev_head(e)
    count = 0
    while count <= count_max:
        #logmsg("'%s'" % GetDisasm(e))
        for i in range(len(arg_instructions)):
            ins = arg_instructions[i] % register
            if ins in GetDisasm(e):
                #logmsg("0x%x - Matches '%s'" % (e, ins))
                # First arrive, first serve
                # We suppose that the instruction closest is the
                # one giving the register value.
                # If we encounter another instruction initializing
                # the register later, we ignore it
                # XXX: if a different register is used, it may give weird result
                # mov     rax, cs:off_46141C0       -> accepted
                # movsxd  rax, dword ptr [rax]      -> rejected
                # mov     [rdx+18h], rax
                if get_operand_type(e, 1) == o_mem:
                    val = get_operand_value(e, 1)
                    #logmsg("Found register value %s: 0x%x" % (register, val))
                    return val
        e = prev_head(e)
        count += 1
    #logmsg("Could not find register value")
    return None

# For a given address, check instructions above looking for potential arguments
# and save this into a dictionary.
# It only works on x86 architecture.
# E.g.: this can be used on some logging functions where one of the argument
#       passed to the logging function contains the caller's function name
#       This allows renaming the caller's function automatically
def get_call_arguments_x86_1(e=get_screen_ea(), count_max=10):
    return get_structure_offsets(e=e, count_max=count_max, reg="esp")

# Works on both 32-bit and 64-bit
# depending on the reg we provide ("rdx", "edx", etc.)
#
# It is generally useful when reg="esp" but we also support parsing from
# other registers in case a structure is filled
def get_structure_offsets(e=get_screen_ea(), count_max=10, reg="esp"):
    args = {}

    # are we a call instruction?
    mnem = print_insn_mnem(e)
    if mnem != "call" and mnem != "jmp":
        logmsg("Error: not a call instruction at 0x%x" % e)
        return None

    # we hardcode the instructions that we are looking for i.e. we don't look
    # for anything else that +4, +8, etc.
    # i.e we don't support yet case where the offset to esp is renamed by IDA

    # direct offset
    # e.g. "mov     dword ptr [esp], offset aUnicorn_admi_0"
    arg_instructions = ["mov     dword ptr [%s]" % reg,
                        "mov     dword ptr [%s+4]" % reg,
                        "mov     dword ptr [%s+8]" % reg,
                        "mov     dword ptr [%s+0Ch]" % reg,
                        "mov     dword ptr [%s+10h]" % reg,
                        "mov     dword ptr [%s+14h]" % reg,
                        "mov     dword ptr [%s+18h]" % reg,
                        "mov     dword ptr [%s+1Ch]" % reg]
    arg_instructions_2 = ["mov     qword ptr [%s]" % reg,
                        "mov     qword ptr [%s+4]" % reg,
                        "mov     qword ptr [%s+8]" % reg,
                        "mov     qword ptr [%s+0Ch]" % reg,
                        "mov     qword ptr [%s+10h]" % reg,
                        "mov     qword ptr [%s+14h]" % reg,
                        "mov     qword ptr [%s+18h]" % reg,
                        "mov     qword ptr [%s+1Ch]" % reg]

    # register so will need an extra step to resolve...
    # e.g. "mov     [esp+4], eax"
    arg_instructions_3 = ["mov     [%s]" % reg,
                          "mov     [%s+4]" % reg,
                          "mov     [%s+8]" % reg,
                          "mov     [%s+0Ch]" % reg,
                          "mov     [%s+10h]" % reg,
                          "mov     [%s+14h]" % reg,
                          "mov     [%s+18h]" % reg,
                          "mov     [%s+1Ch]" % reg]

    # parse arguments, parsing instructions backwards
    e = prev_head(e)
    count = 0
    # we only supports 10 instructions backwards looking for arguments
    while count <= count_max:
        #logmsg("'%s'" % GetDisasm(e))
        for i in range(len(arg_instructions)):
            if arg_instructions[i] in GetDisasm(e):
                #logmsg("0x%x - Matches '%s'" % (e, arg_instructions[i]))
                # First arrive, first serve
                # We suppose that the instruction closest to the call is the
                # one giving the argument.
                # If we encounter another instruction with mov [esp+offset]
                # later with the same offset, we ignore it
                if i not in args.keys():
                    args[i] = get_operand_value(e,1)
                    #logmsg("Found argument %d: 0x%x" % (i, args[i]))
        for i in range(len(arg_instructions_2)):
            if arg_instructions_2[i] in GetDisasm(e):
                #logmsg("Matches '%s'" % arg_instructions_2[i])
                if i not in args.keys():
                    args[i] = get_operand_value(e,1)
                    #logmsg("Found argument %d: 0x%x (2)" % (i, args[i]))
        for i in range(len(arg_instructions_3)):
            if arg_instructions_3[i] in GetDisasm(e):
                #logmsg("Matches '%s'" % arg_instructions_3[i])
                if i not in args.keys():
                    register = print_operand(e, 1)
                    #logmsg("Argument %d based on register %s..." % (i, register))
                    value = get_register_value(e, register)
                    if value != None:
                        args[i] = value
                        #logmsg("Found argument %d: 0x%x (3)" % (i, args[i]))
        e = prev_head(e)
        count += 1
    return args

# see get_call_arguments_x86_1
def get_call_arguments_x86_3(e = get_screen_ea(), count_max = 5):
    args = {}

    # are we a call instruction?
    mnem = print_insn_mnem(e)
    if mnem != "call" and mnem != "jmp":
        logmsg("Error: not a call instruction at 0x%x" % e)
        return None

    # Parse something like:
    # push    offset aSshPacketSocke ; "ssh_packet_socket_callback"
    # push    2
    # push    esi
    # call    log
    args_tmp = []
    # parse arguments, parsing instructions backwards
    e = prev_head(e)
    count = 0
    # we only supports 10 instructions backwards looking for arguments
    while count <= count_max:
        #logmsg("'%s'" % GetDisasm(e))
        # arguments are pushed in reverse order so we get the last arg first
        if "push " in GetDisasm(e):
            args_tmp.append(get_operand_value(e,0))
        e = prev_head(e)
        count += 1
    for i in range(len(args_tmp)):
        args[i] = args_tmp[i]
    return args

# Alternative to get_call_arguments_x86_1(). See get_call_arguments_x86_1() for more
# information.
def get_call_arguments_x86_2(e = get_screen_ea(), count_max = 10):
    args = {}

    # are we a call instruction?
    mnem = print_insn_mnem(e)
    if mnem != "call" and mnem != "jmp":
        logmsg("Error: not a call instruction at 0x%x" % e)
        return None

    # we hardcode the instructions that we are looking for i.e. we don't look
    # for anything else that +4, +8, etc.
    # i.e we don't support yet case where the offset to esp is renamed by IDA
    args_offsets = [0, 4, 8, 0xC, 0x10, 0x14]
    # parse arguments, parsing instructions backwards
    e = prev_head(e)
    count = 0
    # we only supports 10 instructions backwards looking for arguments
    while count <= count_max:
        #logmsg("'%s'" % GetDisasm(e))
        if GetDisasm(e).startswith("mov     [esp"):
            # o_phrase = 3  # Memory Ref [Base Reg + Index Reg] phrase
            if get_operand_type(e,0) == o_phrase:
                # unfortunately we can't test that there is no index register
                # so we ignore for now...
                if 0 not in args.keys():
                    args[0] = get_operand_value(e,1)
            # o_displ = 4 # Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
            if get_operand_type(e,0) == o_displ:
                for i in range(len(args_offsets)):
                    if i == 0:
                        continue # handled by above case
                    if get_operand_value(e,0) == args_offsets[i]:
                        # First arrive, first serve
                        # We suppose that the instruction closest to the call
                        # is the one giving the argument.
                        # If we encounter another instruction with mov [esp+offset]
                        # later with the same offset, we ignore it
                        if i not in args.keys():
                            args[i] = get_operand_value(e,1)
                            #logmsg("Found argument %d: 0x%x" % (i, args[i]))
        e = prev_head(e)
        count += 1
    return args

def get_call_arguments_x64_linux(e = get_screen_ea(), count_max = 10, debug=False):
    return get_call_arguments_x64_generic(e=e, count_max=count_max, debug=debug, linux=True)

def get_call_arguments_x64_windows(e = get_screen_ea(), count_max = 10, debug=False):
    return get_call_arguments_x64_generic(e=e, count_max=count_max, debug=debug, linux=False)
    
# Similar to get_call_arguments_x86_1() but for x86_64. See get_call_arguments_x86_1()
# for more information.
def get_call_arguments_x64_generic(e = get_screen_ea(), count_max = 10, debug=False, linux=True):
    args = {}

    # are we a call instruction?
    mnem = print_insn_mnem(e)
    if mnem != "call" and mnem != "jmp":
        logmsg("Error: not a call instruction at 0x%x" % e)
        return None

    # we only supports 6 arguments for Linux
    if linux:
        arg_instructions_x86 = ["mov     edi",
                                "mov     esi",
                                "mov     edx",
                                "mov     ecx",
                                "mov     r8d",
                                "mov     r9d"]
        arg_instructions_x86_lea = ["lea     edi",
                                    "lea     esi",
                                    "lea     edx",
                                    "lea     ecx",
                                    "lea     r8d",
                                    "lea     r9d"]
        arg_instructions_x64 = ["mov     rdi",
                                "mov     rsi",
                                "mov     rdx",
                                "mov     rcx",
                                "mov     r8",
                                "mov     r9"]
        arg_instructions_x64_lea = ["lea     rdi",
                                    "lea     rsi",
                                    "lea     rdx",
                                    "lea     rcx",
                                    "lea     r8",
                                    "lea     r9"]
    # we only supports 4 arguments for Windows
    else:
        arg_instructions_x86 = ["mov     ecx",
                                "mov     edx",
                                "mov     r8d",
                                "mov     r9d"]
        arg_instructions_x86_lea = ["lea     ecx",
                                    "lea     edx",
                                    "lea     r8d",
                                    "lea     r9d"]
        arg_instructions_x64 = ["mov     rcx",
                                "mov     rdx",
                                "mov     r8",
                                "mov     r9"]
        arg_instructions_x64_lea = ["lea     rcx",
                                    "lea     rdx",
                                    "lea     r8",
                                    "lea     r9"]

    # parse arguments, parsing instructions backwards
    e = prev_head(e)
    count = 0
    # we only supports 10 instructions backwards looking for arguments
    while count <= count_max:
        if debug:
            logmsg("Handling '%s'" % GetDisasm(e))
        for i in range(len(arg_instructions_x86)):
            #if debug:
            #    logmsg("'%s'" % arg_instructions_x86[i])
            if arg_instructions_x86[i] in GetDisasm(e) or \
               arg_instructions_x86_lea[i] in GetDisasm(e) or \
               arg_instructions_x64[i] in GetDisasm(e) or \
               arg_instructions_x64_lea[i] in GetDisasm(e):
                # First arrive, first serve
                # We suppose that the instruction closest to the call is the one giving the argument.
                # If we encounter another instruction with "mov reg" later with the same offset, we ignore it
                if i not in args.keys():
                    args[i] = get_operand_value(e,1)
                    if debug:
                        logmsg("Found argument %d: 0x%x" % (i, args[i]))
        e = prev_head(e)
        count += 1
    return args

# Similar to get_call_arguments_x64_linux() but for ARM 32-bit. See get_call_arguments_x86_1()
# for more information.
def get_call_arguments_arm(e=get_screen_ea(), count_max=10):
    args = {}

    # are we a BL instruction?
    mnem = print_insn_mnem(e)
    if mnem != "BL" and mnem != "SVC" and mnem != "BLNE" and mnem != "BLHI" and mnem != "BLEQ":
        logmsg("Error: not a BL or SVC or BLNE or BLHI or BLEQ instruction at 0x%x" % e)
        return None

    # we only supports 4 arguments
    arg_instructions_arm_mov = ["MOV             R0,",
                                "MOV             R1,",
                                "MOV             R2,",
                                "MOV             R3,"]
    arg_instructions_arm_adr = ["ADR             R0,",
                                "ADR             R1,",
                                "ADR             R2,",
                                "ADR             R3,"]
    arg_instructions_arm_ldr = ["LDR             R0,",
                                "LDR             R1,",
                                "LDR             R2,",
                                "LDR             R3,"]
    arg_instructions_arm_adr2 = ["ADREQ           R0,",
                                 "ADREQ           R1,",
                                 "ADDEQ           R2,",
                                 "ADREQ           R3,"]
    arg_instructions_arm_mov2 = ["MOVEQ           R0,",
                                 "MOVEQ           R1,",
                                 "MOVEQ           R2,",
                                 "MOVEQ           R3,"]
    arg_instructions_arm_adr3 = ["ADRNE           R0,",
                                 "ADRNE           R1,",
                                 "ADDNE           R2,",
                                 "ADRNE           R3,"]
    # parse arguments, parsing instructions backwards
    e = prev_head(e)
    count = 0
    # we only supports 10 instructions backwards looking for arguments
    while count <= count_max:
        #logmsg("'%s'" % GetDisasm(e))
        for i in range(len(arg_instructions_arm_mov)):
            #logmsg("'%s'" % arg_instructions_arm_mov[i])
            #logmsg("Testing index %d" % i)
            # First arrive, first serve
            # We suppose that the instruction closest to the call is the one giving the argument.
            # If we encounter another instruction with "MOV reg" later with the same offset, we ignore it
            if arg_instructions_arm_mov[i] in GetDisasm(e) or \
               arg_instructions_arm_mov2[i] in GetDisasm(e) or \
               arg_instructions_arm_adr[i] in GetDisasm(e) or \
               arg_instructions_arm_adr2[i] in GetDisasm(e) or \
               arg_instructions_arm_adr3[i] in GetDisasm(e):
                if i not in args.keys():
                    args[i] = get_operand_value(e,1)
                    #logmsg("Found argument %d: 0x%x" % (i, args[i]))
            elif arg_instructions_arm_ldr[i] in GetDisasm(e):
                if i not in args.keys():
                    addr = get_operand_value(e,1)
                    args[i] = get_wide_dword(addr)
                    #logmsg("Found argument %d: 0x%x" % (i, args[i]))
        e = prev_head(e)
        count += 1
    return args

def get_call_arguments_x86(e = get_screen_ea(), count_max = 10):
    args = get_call_arguments_x86_1(e, count_max)
    if not args:
        args = get_call_arguments_x86_2(e, count_max)
    if not args:
        args = get_call_arguments_x86_3(e, count_max)
    return args

# Wrapper to have a generic method to get arguments for a function call
# based on internal helpers.
def get_call_arguments(e=get_screen_ea(), count_max=10):
    if ARCHITECTURE == 32:
        args = get_call_arguments_x86(e, count_max)
        if not args:
            args = get_call_arguments_arm(e, count_max)
    else:
        # XXX - we could determine if it is an ELF vs PE and call the right one
        args = get_call_arguments_x64_linux(e, count_max)
        #args = get_call_arguments_x64_windows(e, count_max)
    return args

# find all candidates matching a given binary data
# bytes_str needs to have spaces between each byte
# e.g. "0x%x" % find_binary(get_screen_ea(), 1, '0d c0 a0 e1')
def find_all(bytes_str):
    ret = []
    ea = idc.find_binary(0, 1, bytes_str)
    while ea != idc.BADADDR:
        #print("ea = 0x%x" % ea)
        # If the opcode is found in a function, skip it
        if sark.Line(ea).is_code:
            #print("Existing function at 0x%x" % ea)
            pass
        else:
            ret.append(ea)
        # In ARM every instruction is aligned to 4-bytes
        ea = idc.find_binary(ea + 4, 1, bytes_str)
    return ret

# similar to rename_function_by_aString_being_used()
# but instead of assuming knowing an IDA aString label, takes
# a sequence of characters to look for in order to find the right
# aString
# Note: str can be null terminated or not, or have any byte value
def rename_function_by_ascii_string_being_used(str, funcName, prevFunc=None, nextFunc=None, xref_func=first_xref):

    h = binascii.hexlify(str)
    bytes_str = " ".join([h[i:i+2] for i in range(0, len(h), 2)])
    matches = find_all(bytes_str)
    if len(matches) != 1:
        logmsg("ERROR: rename_function_by_ascii_string_being_used does not support multiple strings")
        return False
    str_addr = matches[0]
    aString = get_name(str_addr, ida_name.GN_VISIBLE)
    if not aString:
        logmsg("ERROR: rename_function_by_ascii_string_being_used did not find any name for aString")
        return False

    return rename_function_by_aString_being_used(aString, funcName, prevFunc=prevFunc, nextFunc=nextFunc, xref_func=xref_func)

# Uses an IDA string label (aString) to find a function and rename it (funcName)
# It uses Xrefs to this string label to locate one function and optionally
# functions surrounding the located function to rename the function
def rename_function_by_aString_being_used(aString, funcName, prevFunc=None, nextFunc=None, xref_func=first_xref):
    global ERROR_MINUS_1
    if name_to_addr(funcName) != None:
        logmsg("%s already defined" % funcName)
        return True

    addr_str = name_to_addr(aString)
    if addr_str == None:
        return False
    addr_str_used = xref_func(addr_str)
    if addr_str_used == None:
        return False
    funcaddr = get_function_addr(addr_str_used)
    if funcaddr == None:
        return False
    if prevFunc != None:
        for i in range(prevFunc):
            logmsg("Going to previous function of 0x%x" % funcaddr)
            funcaddr = get_prev_func(funcaddr)
    if nextFunc != None:
        for i in range(nextFunc):
            logmsg("Going to next function of 0x%x" % funcaddr)
            funcaddr = get_next_func(funcaddr)
    logmsg("%s = 0x%x" % (funcName, funcaddr))
    res = rename_address(funcaddr, funcName)
    if res == None:
        return False
    return True

# Same as rename_function_by_aString_being_used() but with the additional
# capability to filter that the found function does not contain any references
# to some other IDA string labels.
def rename_function_by_aString_being_used_with_filter(aString, funcName, prevFunc=None, nextFunc=None, filtered_aStrings=[], override_old_name=False):
    global ERROR_MINUS_1

    if override_old_name:
        funcaddr = name_to_addr(funcName)
        if funcaddr != None:
            logmsg("Removing old: %s at 0x%x" % (funcName, funcaddr))
            unname_function(funcaddr)
    else:
        if name_to_addr(funcName) != None:
            logmsg("%s already defined" % funcName)
            return True

    addr_str = name_to_addr(aString)
    if addr_str == None:
        return False
    for addr_str_used in get_xrefs(addr_str):
        if addr_str_used == None:
            continue
        funcaddr = get_function_addr(addr_str_used)
        if funcaddr == None:
            continue
        if prevFunc != None:
            for i in range(prevFunc):
                logmsg("Going to previous function of 0x%x" % funcaddr)
                funcaddr = get_prev_func(funcaddr)
        if nextFunc != None:
            for i in range(nextFunc):
                logmsg("Going to next function of 0x%x" % funcaddr)
                funcaddr = get_next_func(funcaddr)
        logmsg("Candidate function: 0x%x == %s ?" % (funcaddr, funcName))
        # Checking now if any filtered referenced string in the candidate function
        bFilter = False
        for aFilteredStr in filtered_aStrings:
            addr_filt_str = name_to_addr(aFilteredStr)
            if addr_filt_str == None:
                continue
            addr_filt_str_used = first_xref(addr_filt_str)
            if addr_filt_str_used == None:
                continue
            funcaddr_filt = get_function_addr(addr_filt_str_used)
            if funcaddr_filt == None:
                continue
            if funcaddr_filt == funcaddr:
                logmsg("This is not the right function: 0x%x == %s" % (funcaddr, aFilteredStr))
                bFilter = True
                break
        if not bFilter:
            break
    if bFilter:
        logmsg("Failed to find the right function")
        return False

    logmsg("%s = 0x%x" % (funcName, funcaddr))
    res = rename_address(funcaddr, funcName)
    if res == None:
        return False
    return True

# ARM only atm
# similar to rename_function_by_aString_surrounding_call()
# but instead of assuming knowing an IDA aString label, takes
# a sequence of characters to look for in order to find the right
# aString
# Note: str can be null terminated or not, or have any byte value
def rename_function_by_ascii_surrounding_call(str, funcName, xref_func=first_xref, count_max=10, filtered_funcs=[], count_filtered_funcs=0, head_func=prev_head):

    h = binascii.hexlify(str)
    bytes_str = " ".join([h[i:i+2] for i in range(0, len(h), 2)])
    matches = find_all(bytes_str)
    if len(matches) != 1:
        logmsg("ERROR: rename_function_by_ascii_surrounding_call does not support multiple strings")
        return False
    str_addr = matches[0]
    aString = get_name(str_addr, ida_name.GN_VISIBLE)
    if not aString:
        logmsg("ERROR: rename_function_by_ascii_surrounding_call did not find any name for aString")
        return False

    return rename_function_by_aString_surrounding_call(aString, funcName, xref_func=xref_func, count_max=count_max, filtered_funcs=filtered_funcs, count_filtered_funcs=count_filtered_funcs, head_func=head_func)

# ARM only atm
# Uses an IDA string label (aString) to find a function and then list all instructions
# backwards looking for ARM Branch With Link instruction "BL". And rename the function
# part of the BL instruction.
def rename_function_by_aString_surrounding_call(aString, funcName, xref_func=first_xref, count_max=10, filtered_funcs=[], count_filtered_funcs=0, head_func=prev_head):
    global ERROR_MINUS_1
    if name_to_addr(funcName) != None:
        logmsg("%s already defined" % funcName)
        return True

    if filtered_funcs and count_filtered_funcs > 0:
        logmsg("ERROR: Only one argument is supported")
        return False

    # required functions to locate funcName
    for filtered_name in filtered_funcs:
        if name_to_addr(filtered_name) == None:
            logmsg("required function: %s missing, can't locate %s" % (filtered_name, funcName))
            return False

    addr_str = name_to_addr(aString)
    if addr_str == None:
        return False
    addr_str_used = xref_func(addr_str)
    if addr_str_used == None:
        return False
    try:
        sark.Function(ea=addr_str_used)
    except sark.exceptions.SarkNoFunction:
        logmsg("No function at 0x%x when handling %s" % (addr_str_used, aString))
        return False

    count = 0
    e = addr_str_used
    bFound = False
    while count <= count_max:
        e = head_func(e)
        line = sark.Line(e)
        #print(line)
        try:
            insn = line.insn
        except sark.exceptions.SarkNoInstruction:
            logmsg("data in the middle of instructions at 0x%x, not supported yet" % e)
            return False
        if insn.mnem == "BL":
            if len(insn.operands) != 1:
                logmsg("Wrong number of operands for BL at 0x%x" % e)
                return False
            curr_func_name = insn.operands[0].text
            # do we need to skip this "BL" or are we done?
            bFiltered = False
            if count_filtered_funcs > 0:
                logmsg("skipping filtered due to count: %d at 0x%x" % (count_filtered_funcs, e))
                count_filtered_funcs -= 1
                bFiltered = True
            else:
                for filtered_name in filtered_funcs:
                    if curr_func_name == filtered_name:
                        logmsg("skipping filtered name: %s at 0x%x" % (filtered_name, e))
                        bFiltered = True
                        break
            if bFiltered:
                count +=1
                continue
            func_addr = name_to_addr(curr_func_name)
            if func_addr == None:
                return False
            rename_address(func_addr, funcName)
            logmsg("%s = 0x%x" % (funcName, func_addr))
            bFound = True
            break
        count += 1
    if not bFound:
        logmsg("ERROR: %s not found" % funcName)
        return False
    return True

# Starts from address (e) and goes backwards until it finds a pointer to another
# segment, stopping after count_max instructions
# seg_info = get_segments_info() is passed to this function
def find_first_pointer_backwards(e, seg_info, count_max=10):
    global SIZE_POINTER
    e -= SIZE_POINTER # we can't use prev_head() because we are not sure DWORDs are defined.
             # Otherwise it goes to a previous DWORD defined by IDA. That can be far away from us :(
    count = 0
    # we only supports 10 addresses backwards
    while count <= count_max:
        addr = get_wide_dword(e)
        #logmsg("%x" % addr)
        if not addr_is_in_one_segment(addr, seg_info):
            break
        e -= SIZE_POINTER
        count += 1
    if count > count_max:
        logmsg("Error: find_first_pointer_backwards: failed to get the first pointer for: 0x%x" % e)
        return False
    # we found a value not from a segment. The right values are the next one.
    e += SIZE_POINTER
    return e

# Returns the number of instruction of a given function
def function_count_instructions(ea = get_screen_ea()):
    E = list(FuncItems(ea))
    return len(E)

# It is indeed to find the basic block that returns from the function
# though it would break if the function had multiple returns
def find_ret_block(addr):
    func = idaapi.get_func(addr)
    # Taken from ex_gdl_qflow_chart.py
    f = idaapi.FlowChart(func)
    for block in f:
        if idaapi.is_ret_block(block.type):
            return block
    return None

def get_bss_end(void):
    return idaapi.get_segm_by_name(".bss").end_ea

# Return the current idb name (without the .idb extension)
def get_idb_name():
    idbpath = get_idb_path()
    idbname = os.path.basename(idbpath)
    if idbname.endswith(".idb"):
        return idbname[:-4]
    if idbname.endswith(".i64"):
        return idbname[:-4]
    return idbname

# Old exported names, to be deprecated
get_current_function = get_function_name
MyGetFuncStartEA = get_function_addr
uname_whatever = unname_address
NameToRVA = name_to_rva
MyLocByName = name_to_addr
MyFirstXrefTo = first_xref
MyFirstXrefOfFirstXrefTo = first_xref_of_first_xref
MySecondXrefTo = second_xref
MyThirdXrefTo = third_xref
MyLastXrefTo = last_xref
MyMakeName = rename_address
get_call_arguments_1 = get_call_arguments_x86_1
get_call_arguments_2 = get_call_arguments_x86_2
get_call_arguments_3 = get_call_arguments_x86_3
get_call_arguments_x64 = get_call_arguments_x64_generic

logmsg("loaded")

if __name__ == "__main__":
    args = get_call_arguments(e=get_screen_ea())
    print(args)