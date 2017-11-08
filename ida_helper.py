#
# Wrappers on some IDA Python functions to help using them :)
#
# It has been heavily tested on x86/x86_64 but could possibly be modified to 
# work on other architectures.
#

from idc import *
from idautils import *
import idaapi

# Attempt to have globals we can use in all other functions without having to
# worry about architecture :)
info = idaapi.get_inf_structure()
if info.is_64bit():
    ERROR_MINUS_1 = 0xffffffffffffffff
    SIZE_POINTER = 8
    ARCHITECTURE = 64
    Pword = Qword
else:
    ERROR_MINUS_1 = 0xffffffff
    SIZE_POINTER = 4
    ARCHITECTURE = 32
    Pword = Dword

# Gives us the xrefs jumping/calling an address
def get_xrefs(ea = ScreenEA()):
    res = []
    for e in XrefsTo(ea):
        #print("[ida_helper] 0x%x -> 0x%x" % (e.frm, e.to))
        res.append(e.frm)
    return res

# Gives the current function's name an address is part of
def get_current_function(ea = ScreenEA()):
    func = idaapi.get_func(ea)
    funcname = GetFunctionName(func.startEA)
    #print("[ida_helper] %X is in %s" % (ea, funcname))
    return funcname

# Gives the current function's address an address is part of
def get_function_addr(ea = ScreenEA()):
    func = idaapi.get_func(ea)
    if func == None:
        return func
    return func.startEA

# Renames an address with a name (and append a digit at the end if already 
# exists)
def rename_function(e, funcname):
    currname = funcname
    count = 1
    if e == None:
        print("[ida_helper] Error: can't rename Nonetype to %s" % funcname)
        return False
    while not MakeName(e, currname):
        currname = "%s_%d" % (funcname, count)
        count += 1
        if count > 100:
            print("[ida_helper] Error: rename_function looped too much for 0x%d -> %s" % (e, funcname))
            return False
    return True

# Remove name for a function (most likely to have sub_XXXXXXXX back after that)
def unname_function(e):
    if not MakeName(e, ""):
        print("[ida_helper] Error: unname_function: could not remove name for function")
        return False
    return True

# For each segment name, save start address, end address in a dictionary
# This can be used to know if a pointer in one segment is part of another
# segment
def get_segments_info():
    # Note this must match the list of segments in the current file
    seg_names = [".init", ".plt", ".text", ".fini", ".rodata", ".eh_frame_hdr",
                 "eh_frame", ".gcc_except_table", ".tdata", ".ctors", ".dtors",
                 ".jcr", ".got", ".got.plt", ".data", "freq_data_section",
                 ".bss", "extern", "abs"]
    res = {}
    for name in seg_names:
        seg = idaapi.get_segm_by_name(name)
        if not seg:
            continue
        res[name] = {}
        res[name]['startEA'] = seg.startEA
    for n in xrange(idaapi.get_segm_qty()):
        seg = idaapi.getnseg(n)
        for name,d in res.items():
            if d['startEA'] == seg.startEA:
                res[name]['ID'] = seg.name # this is an ID, not a name, kthx IDA :(
                res[name]['endEA'] = seg.endEA
    return res

# Checks if an address is part of a given segment
# seq_info = get_segments_info() is passed to this function
def addr_is_in_one_segment(addr, seg_info):
    for name, d in seg_info.items():
        if addr <= seg_info[name]["endEA"] and addr >= seg_info[name]["startEA"]:
            return True
    return False

def NameToRVA(s):
    addr = LocByName(s)
    if addr == ERROR_MINUS_1:
        print("[ida_helper] Error: NameToRVA: Failed to find '%s' symbol" % s)
        return None
    print("[ida_helper] image base 0x%x" % idaapi.get_imagebase())
    return addr - idaapi.get_imagebase()


# Returns the address of any name: function, label, global, etc.
def MyLocByName(s):
    addr = LocByName(s)
    if addr == ERROR_MINUS_1:
        print("[ida_helper] Error: MyLocByName: Failed to find '%s' symbol" % s)
        return None
    return addr

# Gives the first Xref
def MyFirstXrefTo(addr):
    for e in XrefsTo(addr):
        addr = e.frm
        return addr
    print("[ida_helper] Error: MyFirstXrefTo: Failed to find xref for 0x%x" % addr)
    return None

# Gives the second Xref
def MySecondXrefTo(addr):
    i = 1
    for e in XrefsTo(addr):
        frm = e.frm
        if i == 2:
            return frm
        i += 1
    print("[ida_helper] Error: MySecondXrefTo: Failed to find xref for 0x%x" % addr)
    return None

# Gives the third Xref
def MyThirdXrefTo(addr):
    i = 1
    for e in XrefsTo(addr):
        frm = e.frm
        if i == 3:
            return frm
        i += 1
    print("[ida_helper] Error: MyThirdXrefTo: Failed to find xref for 0x%x" % addr)
    return None

# Gives the last Xref
def MyLastXrefTo(addr):
    frm = None
    for e in XrefsTo(addr):
        frm = e.frm
        #print("0x%x" % frm)
    if frm == None:
        print("[ida_helper] Error: MyLastXrefTo: Failed to find xref for 0x%x" % addr)
    return frm

# Gives the current function's address an address is part of 
def MyGetFuncStartEA(ea):
    func = idaapi.get_func(ea)
    if not func:
        print("[ida_helper] Error: MyGetFuncStartEA: Failed to find function start for 0x%x" % ea)
        return None
    return func.startEA

# Rename a function
def MyMakeName(e, funcname):
    if not MakeName(e, funcname):
        print("[ida_helper] Error: MyMakeName: Impossible to rename 0x%x with %s" % (e, funcname))
        return None
    return "OK"

# Find a series of bytes
# e.g. with byteStr = JMP_ESP = '\xff\xe4'
def find_gadget(byteStr):
    seg_info = get_segments_info()
    addr = seg_info[".text"]["startEA"]
    while addr <= seg_info[".text"]["endEA"]:
        b = GetManyBytes(addr, len(byteStr))
        if b == byteStr:
            #print("[ida_helper] Found candidate for gadget %s in .text at 0x%x" % (binascii.hexlify(byteStr), addr))
            return addr
        addr += 1
    if addr > seg_info[".data"]["endEA"]:
        print("[ida_helper] Error: Could not find gadget in .text")
        return None

# For a given address, check instructions above looking for potential arguments
# and save this into a dictionary.
# It only works on x86 architecture.
# E.g.: this can be used on some logging functions where one of the argument
#       passed to the logging function contains the caller's function name
#       This allows renaming the caller's function automatically
def get_call_arguments_1(e = ScreenEA(), count_max = 10):
    args = {}

    # are we a call instruction?
    mnem = GetMnem(e)
    if mnem != "call" and mnem != "jmp":
        print("[ida_helper] Error: not a call instruction at 0x%x" % e)
        return None

    # we hardcode the instructions that we are looking for i.e. we don't look 
    # for anything else that +4, +8, etc.
    # i.e we don't support yet case where the offset to esp is renamed by IDA
    arg_instructions = ["mov     dword ptr [esp]", 
                        "mov     dword ptr [esp+4]", 
                        "mov     dword ptr [esp+8]",
                        "mov     dword ptr [esp+0Ch]", 
                        "mov     dword ptr [esp+10h]", 
                        "mov     dword ptr [esp+14h]"]
    # parse arguments, parsing instructions backwards
    e = PrevHead(e)
    count = 0
    # we only supports 10 instructions backwards looking for arguments
    while count <= count_max:
        #print("[ida_helper] '%s'" % GetDisasm(e))
        for i in range(len(arg_instructions)):
            #print("[ida_helper] '%s'" % arg_instructions[i])
            if arg_instructions[i] in GetDisasm(e):
                # First arrive, first serve
                # We suppose that the instruction closest to the call is the 
                # one giving the argument.
                # If we encounter another instruction with mov [esp+offset] 
                # later with the same offset, we ignore it
                if i not in args.keys():
                    args[i] = GetOperandValue(e,1)
                    #print("[ida_helper] Found argument %d: 0x%x" % (i, args[i]))
        e = PrevHead(e)
        count += 1
    return args

# Alternative to get_call_arguments_1(). See get_call_arguments_1() for more
# information.
def get_call_arguments_2(e = ScreenEA(), count_max = 10):
    args = {}

    # are we a call instruction?
    mnem = GetMnem(e)
    if mnem != "call" and mnem != "jmp":
        print("[ida_helper] Error: not a call instruction at 0x%x" % e)
        return None

    # we hardcode the instructions that we are looking for i.e. we don't look 
    # for anything else that +4, +8, etc.
    # i.e we don't support yet case where the offset to esp is renamed by IDA
    args_offsets = [0, 4, 8, 0xC, 0x10, 0x14]
    # parse arguments, parsing instructions backwards
    e = PrevHead(e)
    count = 0
    # we only supports 10 instructions backwards looking for arguments
    while count <= count_max:
        #print("[ida_helper] '%s'" % GetDisasm(e))
        if GetDisasm(e).startswith("mov     [esp"):
            # o_phrase = 3  # Memory Ref [Base Reg + Index Reg] phrase
            if GetOpType(e,0) == o_phrase:
                # unfortunately we can't test that there is no index register 
                # so we ignore for now...
                if 0 not in args.keys():
                    args[0] = GetOperandValue(e,1)
            # o_displ = 4 # Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
            if GetOpType(e,0) == o_displ:
                for i in range(len(args_offsets)):
                    if i == 0:
                        continue # handled by above case
                    if GetOperandValue(e,0) == args_offsets[i]:
                        # First arrive, first serve
                        # We suppose that the instruction closest to the call 
                        # is the one giving the argument.
                        # If we encounter another instruction with mov [esp+offset] 
                        # later with the same offset, we ignore it
                        if i not in args.keys():
                            args[i] = GetOperandValue(e,1)
                            #print("[ida_helper] Found argument %d: 0x%x" % (i, args[i]))
        e = PrevHead(e)
        count += 1
    return args

# Similar to get_call_arguments_1() but for x86_64. See get_call_arguments_1() 
# for more information.
def get_call_arguments_x64(e = ScreenEA(), count_max = 10):
    args = {}

    # are we a call instruction?
    mnem = GetMnem(e)
    if mnem != "call" and mnem != "jmp":
        print("[ida_helper] Error: not a call instruction at 0x%x" % e)
        return None

    # we only supports 6 arguments
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
    # parse arguments, parsing instructions backwards
    e = PrevHead(e)
    count = 0
    # we only supports 10 instructions backwards looking for arguments
    while count <= count_max:
        #print("[ida_helper] '%s'" % GetDisasm(e))
        for i in range(len(arg_instructions_x86)):
            #print("[ida_helper] '%s'" % arg_instructions_x86[i])
            if arg_instructions_x86[i] in GetDisasm(e) or \
               arg_instructions_x86_lea[i] in GetDisasm(e) or \
               arg_instructions_x64[i] in GetDisasm(e) or \
               arg_instructions_x64_lea[i] in GetDisasm(e):
                # First arrive, first serve
                # We suppose that the instruction closest to the call is the one giving the argument.
                # If we encounter another instruction with "mov reg" later with the same offset, we ignore it
                if i not in args.keys():
                    args[i] = GetOperandValue(e,1)
                    #print("[ida_helper] Found argument %d: 0x%x" % (i, args[i]))
        e = PrevHead(e)
        count += 1
    return args

# Wrapper to have a generic method to get arguments for a function call
# based on internal helpers.
def get_call_arguments(e = ScreenEA(), count_max = 10):
    if ARCHITECTURE == 32:
        args = get_call_arguments_1(e, count_max)
        if not args:
            args = get_call_arguments_2(e, count_max)
    else:
        args = get_call_arguments_x64(e, count_max)
    return args

# Uses an IDA string label (aString) to find a function and rename it (funcName)
# It uses Xrefs to this string label to locate one function and optionally 
# functions surrounding the located function to rename the function
def rename_function_by_aString_being_used(aString, funcName, prevFunc=None, nextFunc=None, xref_func=MyFirstXrefTo):
    global ERROR_MINUS_1
    if MyLocByName(funcName) != None:
        print("[ida_helper] %s already defined" % funcName)
        return True

    addr_str = MyLocByName(aString)
    if addr_str == None:
        return False
    addr_str_used = xref_func(addr_str)
    if addr_str_used == None:
        return False
    funcaddr = MyGetFuncStartEA(addr_str_used)
    if funcaddr == None:
        return False
    if prevFunc != None:
        for i in range(prevFunc):
            print("[ida_helper] Going to previous function of 0x%x" % funcaddr)
            funcaddr = PrevFunction(funcaddr)
    if nextFunc != None:
        for i in range(nextFunc):
            print("[ida_helper] Going to next function of 0x%x" % funcaddr)
            funcaddr = NextFunction(funcaddr)
    print("[ida_helper] %s = 0x%x" % (funcName, funcaddr))
    res = MyMakeName(funcaddr, funcName)
    if res == None:
        return False
    return True

# Same as rename_function_by_aString_being_used() but with the additional
# capability to filter that the found function does not contain any references
# to some other IDA string labels.
def rename_function_by_aString_being_used_with_filter(aString, funcName, prevFunc=None, nextFunc=None, filtered_aStrings=[], override_old_name=False):
    global ERROR_MINUS_1
    
    if override_old_name:
        funcaddr = MyLocByName(funcName)
        if funcaddr != None:
            print("[ida_helper] Removing old: %s at 0x%x" % (funcName, funcaddr))
            unname_function(funcaddr)
    else:
        if MyLocByName(funcName) != None:
            print("[ida_helper] %s already defined" % funcName)
            return True
    
    addr_str = MyLocByName(aString)
    if addr_str == None:
        return False
    for addr_str_used in get_xrefs(addr_str):
        if addr_str_used == None:
            continue
        funcaddr = MyGetFuncStartEA(addr_str_used)
        if funcaddr == None:
            continue
        if prevFunc != None:
            for i in range(prevFunc):
                print("[ida_helper] Going to previous function of 0x%x" % funcaddr)
                funcaddr = PrevFunction(funcaddr)
        if nextFunc != None:
            for i in range(nextFunc):
                print("[ida_helper] Going to next function of 0x%x" % funcaddr)
                funcaddr = NextFunction(funcaddr)
        print("[ida_helper] Candidate function: 0x%x == %s ?" % (funcaddr, funcName))
        # Checking now if any filtered referenced string in the candidate function
        bFilter = False 
        for aFilteredStr in filtered_aStrings:
            addr_filt_str = MyLocByName(aFilteredStr)
            if addr_filt_str == None:
                continue
            addr_filt_str_used = MyFirstXrefTo(addr_filt_str)
            if addr_filt_str_used == None:
                continue
            funcaddr_filt = MyGetFuncStartEA(addr_filt_str_used)
            if funcaddr_filt == None:
                continue
            if funcaddr_filt == funcaddr:
                print("[ida_helper] This is not the right function: 0x%x == %s" % (funcaddr, aFilteredStr))
                bFilter = True
                break
        if not bFilter:
            break
    if bFilter:
        print("[ida_helper] Failed to find the right function")
        return False
        
    print("[ida_helper] %s = 0x%x" % (funcName, funcaddr))
    res = MyMakeName(funcaddr, funcName)
    if res == None:
        return False
    return True

# Starts from address (e) and goes backwards until it finds a pointer to another
# segment, stopping after count_max instructions
# seq_info = get_segments_info() is passed to this function
def find_first_pointer_backwards(e, seg_info, count_max=10):
    global SIZE_POINTER
    e -= SIZE_POINTER # we can't use PrevHead() because we are not sure DWORDs are defined.
             # Otherwise it goes to a previous DWORD defined by IDA. That can be far away from us :(
    count = 0
    # we only supports 10 addresses backwards
    while count <= count_max:
        addr = Dword(e)
        #print("[ida_helper] %x" % addr)
        if not addr_is_in_one_segment(addr, seg_info):
            break
        e -= SIZE_POINTER
        count += 1
    if count > count_max:
        print("[ida_helper] Error: find_first_pointer_backwards: failed to get the first pointer for: 0x%x" % e)
        return False
    # we found a value not from a segment. The right values are the next one.
    e += SIZE_POINTER
    return e
    
# Returns the number of instruction of a given function
def function_count_instructions(ea = ScreenEA()):
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
    return idaapi.get_segm_by_name(".bss").endEA

# Return the current idb name (without the .idb extension)
def get_idb_name():
    idbpath = GetIdbPath()
    idbname = os.path.basename(idbpath)
    if idbname.endswith(".idb"):
        return idbname[:-4]
    if idbname.endswith(".i64"):
        return idbname[:-4]
    return idbname

print("[ida_helper] loaded")
