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
        disasm_line = GetDisasm(e)
        #logmsg("'%s'" % disasm_line)
        for i in range(len(arg_instructions)):
            ins = arg_instructions[i] % register
            if ins in disasm_line:
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
        logmsg("Error: not a x86 call instruction at 0x%x" % e)
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
        disasm_line = GetDisasm(e)
        #logmsg("'%s'" % disasm_line)
        for i in range(len(arg_instructions)):
            if arg_instructions[i] in disasm_line:
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
            if arg_instructions_2[i] in disasm_line:
                #logmsg("Matches '%s'" % arg_instructions_2[i])
                if i not in args.keys():
                    args[i] = get_operand_value(e,1)
                    #logmsg("Found argument %d: 0x%x (2)" % (i, args[i]))
        for i in range(len(arg_instructions_3)):
            if arg_instructions_3[i] in disasm_line:
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
        logmsg("Error: not a x86 call instruction at 0x%x" % e)
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
        disasm_line = GetDisasm(e)
        #logmsg("'%s'" % disasm_line)
        # arguments are pushed in reverse order so we get the last arg first
        if "push " in disasm_line:
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
        logmsg("Error: not a x86 call instruction at 0x%x" % e)
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
        disasm_line = GetDisasm(e)
        #logmsg("'%s'" % disasm_line)
        if disasm_line.startswith("mov     [esp"):
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
        logmsg("Error: not a x86 call instruction at 0x%x" % e)
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
        disasm_line = GetDisasm(e)
        if debug:
            logmsg("Handling '%s'" % disasm_line)
        for i in range(len(arg_instructions_x86)):
            #if debug:
            #    logmsg("'%s'" % arg_instructions_x86[i])
            instruction_list = [arg_instructions_x86[i],
                                 arg_instructions_x86_lea[i],
                                 arg_instructions_x64[i],
                                 arg_instructions_x64_lea[i]]
            if any(instruction in disasm_line for instruction in instruction_list):
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
    cached_args = {}

    # are we a BL instruction?
    mnem = print_insn_mnem(e)
    if mnem != "B" and mnem != "BL" and mnem != "SVC" and mnem != "BLNE" and mnem != "BLHI" and mnem != "BLEQ":
        logmsg("Error: not a BL or SVC or BLNE or BLHI or BLEQ instruction at 0x%x" % e)
        return None

    arg_instructions_arm_add_pc = ["ADD R0, PC, R0",
                                "ADD R1, PC, R1",
                                "ADD R2, PC, R2",
                                "ADD R3, PC, R3"]
    arg_instructions_arm_add = ["ADD R0, R0,",
                                "ADD R1, R1",
                                "ADD R2, R2",
                                "ADD R3, R3"]

    # we only supports 4 arguments
    arg_instructions_arm_mov = ["MOV     R0,",
                                "MOV     R1,",
                                "MOV     R2,",
                                "MOV     R3,"]
    arg_instructions_arm_adr = ["ADR     R0,",
                                "ADR     R1,",
                                "ADR     R2,",
                                "ADR     R3,"]
    arg_instructions_arm_ldr = ["LDR     R0,",
                                "LDR     R1,",
                                "LDR     R2,",
                                "LDR     R3,"]
    arg_instructions_arm_adr2 = ["ADREQ   R0,",
                                 "ADREQ   R1,",
                                 "ADDEQ   R2,",
                                 "ADREQ   R3,"]
    arg_instructions_arm_mov2 = ["MOVEQ   R0,",
                                 "MOVEQ   R1,",
                                 "MOVEQ   R2,",
                                 "MOVEQ   R3,"]
    arg_instructions_arm_adr3 = ["ADRNE   R0,",
                                 "ADRNE   R1,",
                                 "ADDNE   R2,",
                                 "ADRNE   R3,"]
    # parse arguments, parsing instructions backwards
    e = prev_head(e)
    count = 0
    # we only supports 10 instructions backwards looking for arguments
    while count <= count_max:
        disasm_line = GetDisasm(e)
        #logmsg("'%s'" % disasm_line)
        for i in range(len(arg_instructions_arm_mov)):
            #logmsg("'%s'" % arg_instructions_arm_mov[i])
            #logmsg("Testing index %d" % i)
            # First arrive, first serve
            # We suppose that the instruction closest to the call is the one giving the argument.
            # If we encounter another instruction with "MOV reg" later with the same offset, we ignore it
            instruction_list = [arg_instructions_arm_mov[i],
                                arg_instructions_arm_mov2[i],
                                arg_instructions_arm_adr[i],
                                arg_instructions_arm_adr[i],
                                arg_instructions_arm_adr3[i]]
            add_pc_instruction_list = [arg_instructions_arm_add_pc[i]]
            add_instruction_list = [arg_instructions_arm_add[i]]
            # Remove all spaces to get rid of indentation discrepancies
            # .text:000492B4 64 01 9F E5                 LDR             R0, =(aHydraSSystemNo_0 - 0x492C8) ; "hydra: %s: System not yet ready. Waitin"...
            # .text:000492B8 04 20 A0 E1                 MOV             R2, R4
            # .text:000492BC 06 10 A0 E1                 MOV             R1, R6
            # .text:000492C0 00 00 8F E0                 ADD             R0, PC, R0 ; "hydra: %s: System not yet ready. Waitin"...
            # .text:000492C4 31 8B FF EB                 BL              printf
            # .text:000492C8 01 40 54 E2                 SUBS            R4, R4, #1
            if any(instruction.replace(" ", "") in disasm_line.replace(" ", "") for instruction in add_pc_instruction_list):
                if i not in cached_args.keys():
                    cached_args[i] = 0
                val = e + 4 + 4 # +2 instructions due to cached instruction pipeline, see 0x492C8 instead of 0x492C0 above
                #logmsg("Cached pc = 0x%x for %d" % (val, i))
                cached_args[i] += val
            # .text:004397D4 84 10 9F E5                 LDR             R1, =(aNetworkConnect - 0x4397E8) ; "network_connect_state"
            # .text:004397D8 84 00 9F E5                 LDR             R0, =(aSEntryPortIfPD - 0x4397F4) ; "%s: entry.  port_if=%p, devdep=%p\n"
            # .text:004397DC 04 20 A0 E1                 MOV             R2, R4
            # .text:004397E0 01 10 8F E0                 ADD             R1, PC, R1 ; "network_connect_state"
            # .text:004397E4 1C 30 94 E5                 LDR             R3, [R4,#0x1C]
            # .text:004397E8 44 10 81 E2                 ADD             R1, R1, #0x44 ; 'D'
            # .text:004397EC 00 00 8F E0                 ADD             R0, PC, R0 ; "%s: entry.  port_if=%p, devdep=%p\n"
            # .text:004397F0 E6 C9 EF EB                 BL              printf
            elif any(instruction.replace(" ", "") in disasm_line.replace(" ", "") for instruction in add_instruction_list):
                if i not in cached_args.keys():
                    cached_args[i] = 0
                val = get_operand_value(e, 2)
                #logmsg("Cached addition = 0x%x for %d" % (val, i))
                cached_args[i] += val
            elif any(instruction.replace(" ", "") in disasm_line.replace(" ", "") for instruction in instruction_list):
                if i not in args.keys():
                    args[i] = get_operand_value(e,1)
                    #logmsg("Found argument %d: 0x%x" % (i, args[i]))
            elif arg_instructions_arm_ldr[i].replace(" ", "") in disasm_line.replace(" ", ""):
                if i not in args.keys():
                    addr = get_operand_value(e,1)
                    args[i] = get_wide_dword(addr)
                    if i in cached_args.keys():
                        #logmsg("args[i] = 0x%x" % (args[i]))
                        args[i] += cached_args[i]
                        #logmsg("Adjusted args[i] = 0x%x" % (args[i]))
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
        if info.procName == "ARM":
            args = get_call_arguments_arm(e, count_max)
        else:
            args = get_call_arguments_x86(e, count_max)
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

#.data:0012E70C off_12E70C      DCD aGetstr             ; DATA XREF: sub_1A104:loc_1A15C↑o
#.data:0012E70C                                         ; .text:off_1A1C8↑o
#.data:0012E70C                                         ; "getstr"
#.data:0012E710                 DCD sub_9AE90
#.data:0012E714                 DCD aNvramGet_0         ; "nvram_get"
#.data:0012E718                 DCD sub_19950
#.data:0012E71C                 DCD aNvramMatch         ; "nvram_match"
#...
#.data:0012F114                 DCD aGetArmorServer_0   ; "get_armor_server"
#.data:0012F118                 DCD sub_A72A8
#.data:0012F11C                 ALIGN 0x10
def rename_table_of_functions_by_ascii_string_being_used(str, table_name, xref_func=first_xref, simulate=False, replace_chars_func=None, prev_value=0x0):
    """This function takes a string as an argument and look for a table of strings/function pointers
    where each string is the name of the function following.
    
    It will use the string and go backwards until it find a zero value to know it went to the beginning
    of the table. It will stop when encountering a NULL string.
    
    :param str: one of the string present in the table
    :param table_name: the name of the table to use for renaming it
    :param simulate: True if you just want to simulate instead of actually renaming. False by default.
    :param replace_chars_func: If not None, is a function to call to replace characters in the string
                               before using it as a function name. E.g. when having the "bd_genie_prodcut_register.cgi"
                               string, it allows
    :param prev_value: integer value of the size of a pointer that is used to know when we reached
                       the beginning of the table (i.e. it is the value before that start of the table)
    """

    global SIZE_POINTER
    bytes_str = " ".join("%02x" % x for x in str.encode("utf-8"))
    matches = find_all(bytes_str)
    if len(matches) != 1:
        logmsg("ERROR: rename_table_of_functions_by_ascii_string_being_used does not support multiple strings: %s" % (["%x" % x for x in matches]))
        return False
    addr_str = matches[0]
    # aString = get_name(addr_str, ida_name.GN_VISIBLE)
    # if not aString:
    #     logmsg("ERROR: rename_table_of_functions_by_ascii_string_being_used did not find any name for aString")
    #     return False
    addr_str_used = xref_func(addr_str)
    if addr_str_used == None:
        return False
    addr_table = find_first_value_backwards(addr_str_used, prev_value, count_max=50)
    logmsg("table address: 0x%x" % addr_table)
    if not simulate:
        rename_function(addr_table, table_name)
    
    e = addr_table
    count = 0
    while True:
        string_addr = get_wide_dword(e)
        if string_addr == 0x0:
            break
        func_addr = get_wide_dword(e + SIZE_POINTER)
        funcname = get_strlit_contents(string_addr).decode('utf-8')
        if replace_chars_func != None:
            funcname = replace_chars_func(funcname)
        e += 2*SIZE_POINTER
        current_func_name = get_func_name(func_addr)
        if current_func_name.startswith("sub_"):
            logmsg("0x%x -> %s" % (func_addr, funcname))
            if not simulate:
                rename_function(func_addr, funcname)
            count += 1
        else:
            pass
            #logmsg("0x%x -> %s (skipped. already named: %s)" % (current_func_addr, funcname, current_func_name))
    logmsg("Renamed %d functions" % count)

# similar to rename_function_by_aString_being_used()
# but instead of assuming knowing an IDA aString label, takes
# a sequence of characters to look for in order to find the right
# aString
# Note: str can be null terminated or not, or have any byte value
def rename_function_by_ascii_string_being_used(str, funcName, prevFunc=None, nextFunc=None, xref_func=first_xref):

    # XXX - may need to fix the hexlify to be python3 compliant like in
    # rename_table_of_functions_by_ascii_string_being_used()
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

def rename_logging_function(log_funcname, funcstr_helpers, simulate=False):
    """Find a "logging" function in a binary and rename it. The idea is this
    logging function can then be used to rename lots of other functions, see
    rename_using_logging_function() and rename_functions_using_logging_function().
    
    :param log_funcname: string for the name of the logging function we want to use
                         once we find it.
    :param funcstr_helpers: a list of aNames that are used as argument for the logging
                            function we are looking for (i.e. IDA symbols names such as 
                            "aErrorConvertin" in the below example)
    :param simulate: True if you just want to simulate instead of actually renaming. False by default.


    E.g. in the below, sub_BAC8() is a logging function. So we want to rename it.

    .text:0000C704 ; int __fastcall sub_C704(const char *, const char *, int, int)
    .text:0000C704 sub_C704  
    ...
    .text:0000C9B8                 LDR             R1, =aErrorConvertin ; "Error converting ip address in %s()\n"
    .text:0000C9BC                 MOV             R0, #2
    .text:0000C9C0                 LDR             R2, =aUpnpCallbackSe ; "upnp_callback_send"
    .text:0000C9C4                 BL              sub_BAC8

    i.e. 
    
    sub_BAC8(2, "Error converting ip address in %s()\n", "upnp_callback_send");
    
    Then we will be able to rename all functions using that logging function, since that logging function
    takes the name of the calling function as an argument. So e.g. above we can rename sub_C704()
    into upnp_callback_send().
    """

    global ERROR_MINUS_1
    tmp = get_name_ea_simple(log_funcname)
    if tmp != ERROR_MINUS_1:
        logmsg("rename_logging_function: '%s' already defined" % log_funcname)
        return True

    log_funcaddr = None
    for s in funcstr_helpers:
        addrstr = get_name_ea_simple(s)
        if addrstr == ERROR_MINUS_1:
            logmsg("rename_logging_function: Skipping using %s" % (s))
            continue

        for e in get_xrefs(addrstr):
            e = next_head(e)
            count = 0
            # we only supports 10 instructions forwards looking for the "call <log_funcaddr>"
            # but it should be enough because the funcstr_helpers strings are passed
            # as arguments to the call
            while count <= 10:
                disass = GetDisasm(e)
                print("%x -> %s" % (e, disass))
                if disass.startswith("call") or disass.startswith("BL"):
                    log_funcaddr = get_operand_value(e, 0)
                    break
                e = next_head(e)
                count += 1
            if log_funcaddr != None:
                break

    if log_funcaddr == None:
        logmsg("%s not found" % log_funcname)
        return False
    logmsg("Found %s = 0x%x" % (log_funcname, log_funcaddr))

    if simulate:
        return True

    if not set_name(log_funcaddr, log_funcname, SN_CHECK):
        logmsg("Should not happen: failed to rename to %s" % log_funcname)
        return False
    return True

# It would allow renaming functions like 
# "acsd_extract_token_val" below using a logging function like "printf"
#
# int __fastcall acsd_extract_token_val(char *src, char *needle, char *a3)
# {
#   // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]
# 
#   if ( src )
#     strcpy(buffer, src);
#   if ( (dword_25398 & 8) != 0 )
#     printf("ACSD >>%s(%d): copydata: %s\n", "acsd_extract_token_val", 0x3D, buffer);
#
# .text:0001343C acsd_extract_token_val  
# ...
# .text:000134D0 loc_134D0                               ; CODE XREF: acsd_extract_token_val+30↑j
# .text:000134D0                 MOV             R2, #0x3D ; '='
# .text:000134D4                 LDR             R1, =aAcsdExtractTok ; "acsd_extract_token_val"
# .text:000134D8                 MOV             R3, SP
# .text:000134DC                 LDR             R0, =aAcsdSDCopydata ; "ACSD >>%s(%d): copydata: %s\n"
# .text:000134E0                 BL              printf
#
# E.g. go to "000134E0" and execute:
def rename_using_logging_function(e=get_screen_ea(), log_funcname="printf", logfunc_arg_number=1, logfunc_preprocessor=None, check_args_callback=None, simulate=False, debug=False):
    """Rename a function assuming a logging function is being called
    
    :param e: address where the call/jmp/bl/etc. instruction is
    :param log_funcname: string for the function's name that is logging
    :param logfunc_arg_number: index to the argument number (starts at 0 as is indexing in an array)
    :param logfunc_preprocessor: If not None, function to call and passing logfunc_arg_number argument to get the
                                 real function name. E.g. if we have a logging function like 
                                 perror("func_name: error xxx\n"), we want to retrieve what is before 
                                 the ":"
    :param check_args_callback: callback function that checks if the arguments to log_funcname look valid
                                before renaming a target. None if don't want to provide one.
                                This function takes a single argument: the dictionary of arguments 
                                as returned by get_call_arguments()
    :param simulate: True if you just want to simulate instead of actually renaming. False by default.
    :param debug: set to True if you want to see more logs while debugging
    :return: None
    """

    # NOTE: We don't check if it is call/jmp/bl/etc instruction as is done
    # inside get_call_arguments() for the different architectures, etc.

    if debug:
        logmsg("rename_using_logging_function(): 0x%x" % e)
    
    if not debug:
        # early skip, avoid erroring too much due to quirks in logging functions being called
        func = idaapi.get_func(e)
        if not func:
            logmsg("Skipping: Could not find function for %x" % e)
            return False
        current_func_addr = func.start_ea
        current_func_name = get_func_name(current_func_addr)
        if not current_func_name.startswith("sub_"):
            return False # was previously renamed
    
    # parse arguments, parsing instructions backwards
    args = get_call_arguments(e, count_max=35)
    if not args:
        logmsg("0x%x: get_call_arguments failed" % e)
        return False
    if logfunc_arg_number not in args.keys():
        logmsg("0x%x: Could not find argument %d in %s args" % (e, logfunc_arg_number, log_funcname))
        return False
    if check_args_callback != None and not check_args_callback(args):
        logmsg("0x%x: Skipping due to non-compliant arguments for %s" % (e, log_funcname))
        return False
    
    # Is the 3rd argument an offset to a string as it should be?
    # note args[0] is the first argument, args[1] the second, etc.
    seg_info = get_segments_info()
    if debug:
        logmsg(args)
    if not addr_is_in_one_segment(args[logfunc_arg_number], seg_info):
        logmsg("0x%x -> 0x%x not a valid offset" % (e, args[logfunc_arg_number]))
        return False

    string = get_strlit_contents(args[logfunc_arg_number])
    if string == None:
        logmsg("0x%x -> 0x%x not a valid string" % (e, args[logfunc_arg_number]))
        return False
    string = string.decode('utf-8')
    if logfunc_preprocessor == None:
        funcname = string
    else:
        funcname = logfunc_preprocessor(string)
        if not funcname:
            logmsg("Skipping: Could not find a valid function with processor for %x" % e)
            return False
    func = idaapi.get_func(e)
    if not func:
        logmsg("Skipping: Could not find function for %x" % e)
        return False
    current_func_addr = func.start_ea
    current_func_name = get_func_name(current_func_addr)
    if current_func_name.startswith("sub_"):
        logmsg("0x%x -> %s" % (current_func_addr, funcname))
        if not simulate:
            if not rename_function(current_func_addr, funcname):
                return False
    else:
        pass
        #logmsg("0x%x -> %s (skipped. already named: %s)" % (current_func_addr, funcname, current_func_name))

    return True

def rename_functions_using_logging_function(log_funcname, logfunc_arg_number, logfunc_preprocessor=None, check_args_callback=None, simulate=False, debug=False):
    """Rename all the functions assuming a logging function is being called
    
    :param log_funcname: string for the function's name that is logging
    :param logfunc_arg_number: index to the argument number (starts at 0 as is indexing in an array)
    :param logfunc_preprocessor: If not None, function to call and passing logfunc_arg_number argument to get the
                                 real function name. E.g. if we have a logging function like 
                                 perror("func_name: error xxx\n"), we want to retrieve what is before 
                                 the ":"
    :param check_args_callback: callback function that checks if the arguments to log_funcname look valid
                                before renaming a target. None if don't want to provide one.
                                This function takes a single argument: the dictionary of arguments 
                                as returned by get_call_arguments()
    :param simulate: True if you just want to simulate instead of actually renaming. False by default.
    :return: -1 if the logging function name was not found. The number of renamed functions otherwise
    """

    global ERROR_MINUS_1

    count = 0
    my_log_addr = get_name_ea_simple(log_funcname)
    if my_log_addr == ERROR_MINUS_1:
        logmsg("ERROR: you need to find %s first. Use rename_using_logging_function() first or find it manually by searching for strings that look like function names" % log_funcname)
        return -1
    for e in get_xrefs(my_log_addr):
        #logmsg("0x%x" % e)
        # we don't check for return values because we better rename as many functions as possible
        # even if one failed e.g. because code was defined by not as a function.
        if rename_using_logging_function(e, log_funcname=log_funcname, logfunc_arg_number=logfunc_arg_number, logfunc_preprocessor=logfunc_preprocessor, check_args_callback=check_args_callback, simulate=simulate, debug=debug):
            count += 1

    logmsg("Renamed %d functions" % count)
    return count

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

# Starts from address (e) and goes backwards until it finds a value
def find_first_value_backwards(e, value, count_max=10):
    global SIZE_POINTER
    e -= SIZE_POINTER # we can't use prev_head() because we are not sure DWORDs are defined.
             # Otherwise it goes to a previous DWORD defined by IDA. That can be far away from us :(
    count = 0
    # we only supports 10 addresses backwards
    while count <= count_max:
        current_value = get_wide_dword(e)
        #logmsg("%x" % addr)
        if current_value == value:
            break
        e -= SIZE_POINTER
        count += 1
    if count > count_max:
        logmsg("Error: find_first_pointer_backwards: failed to get the first pointer for: 0x%x" % e)
        return False
    # we found a value. The right values are the next one.
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
