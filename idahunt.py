#!/usr/bin/python3
#
# This file is part of idahunt.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# Script to automatically analyse lots of files with IDA Pro, rename
# functions/globals/etc. in several IDBs, open several IDBs or
# hunt for what you want in several IDBs using an IDA Python script.
#
# Tested under Windows and Linux.
#
# IDA command line switches:
# https://www.hex-rays.com/products/ida/support/idadoc/417.shtml

import argparse
import os
import re
import sys
import subprocess
import time
import glob
import filelock
import struct

def logmsg(s, end=None, debug=True):
    if not debug:
        return
    if type(s) == str:
        if end != None:
            print("[idahunt] " + s, end=end)
        else:
            print("[idahunt] " + s)
    else:
        print(s)

# https://gist.github.com/polyvertex/b6d337fec7011a0f9292
def iglob_hidden(*args, **kwargs):
    """A glob.iglob that include dot files and hidden files"""
    old_ishidden = glob._ishidden
    glob._ishidden = lambda x: False
    try:
        yield from glob.iglob(*args, **kwargs)
    finally:
        glob._ishidden = old_ishidden

def path_to_module_string(p):
    return p.replace("/", ".").replace("\\", ".")

# Automatically detects the architecture for PE files
def detect_arch_pe_files(filename):
    IMAGE_FILE_MACHINE_I386 = 0x014c
    IMAGE_FILE_MACHINE_IA64 = 0x0200
    IMAGE_FILE_MACHINE_AMD64 = 0x8664
    IMAGE_FILE_MACHINE_ARMTHUMB_MIXED = 0x01c2
    IMAGE_FILE_MACHINE_ARM64 = 0xAA64

    arch = None
    f = open(filename, "rb")
    f.seek(60)
    s = f.read(4)
    header_offset = struct.unpack("<L", s)[0]
    f.seek(header_offset+4)
    s = f.read(2)
    machine = struct.unpack("<H", s)[0]
    if machine == IMAGE_FILE_MACHINE_I386 or machine == IMAGE_FILE_MACHINE_ARMTHUMB_MIXED:
        arch = 32
    elif machine == IMAGE_FILE_MACHINE_IA64 or machine == IMAGE_FILE_MACHINE_AMD64 or machine == IMAGE_FILE_MACHINE_ARM64:
        arch = 64
    else:
        logmsg("Unknown architecture detected for %s. Ignoring" % filename)
    f.close()

    return arch

# Automatically detects the architecture for ELF files
def detect_arch_elf_files(filename):
    arch = None
    f = open(filename, "rb")
    f.seek(4)
    s = f.read(1)
    if s == b"\x01":
        arch = 32
    elif s == b"\x02":
        arch = 64
    else:
        logmsg("Unknown architecture detected for %s. Ignoring" % filename)
    f.close()

    return arch

def detect_arch(filename):
    arch = None
    f = open(filename, "rb")
    pe = f.read(2)
    f.seek(0)
    elf = f.read(4)
    f.close()
    if pe == b"MZ":
        arch = detect_arch_pe_files(filename)
    elif elf == b"\x7fELF":
        arch = detect_arch_elf_files(filename)
    else:
        logmsg("Not an EXE or ELF file. Ignoring automatic architecture detection")

    return arch

# Does the initial auto-analysis when we first open a file in IDA
# Returns False if does not do anything, the subprocess if it was created
# of True if it was listing only.
def analyse_file(ida_executable, infile, logfile, idbfile, verbose, ida_args=None, script=None, list_only=False):
    if os.path.isfile(idbfile):
        logmsg("Skipping existing IDB %s. Analysis has already been made" % idbfile, debug=verbose)
        return False
    if os.path.isfile(infile + ".id0"):
        logmsg("Skipping existing id0 %s. Close IDB first." % (infile + ".id0"), debug=verbose)
        return False
    logmsg("Analysing %s" % infile)
    # We use -o below to gracefully handle symlinks
    if ida_args:
        cmd = [ida_executable, "-B", "-o%s" % idbfile, "-L%s"% logfile] + ida_args + [infile]
    else:
        cmd = [ida_executable, "-B", "-o%s" % idbfile, "-L%s"% logfile, infile]
    if verbose:
        logmsg("%s" % " ".join(cmd))
    shell=True
    if os.name == "posix":
        shell=False

    if not list_only:
        return subprocess.Popen(cmd, shell)
    else:
        return True

# Re-open an existing IDB
# Returns False if does not do anything, the subprocess if it was created
# of True if it was listing only.
def open_file(ida_executable, infile, logfile, idbfile, verbose, ida_args=None, script=None, list_only=False):
    if not os.path.isfile(idbfile):
        logmsg("Skipping no existing IDB %s. Execute --analyse first." % idbfile, debug=verbose)
        return False
    if os.path.isfile(infile + ".id0"):
        logmsg("Skipping existing id0 %s. Close IDB first." % (infile + ".id0"), debug=verbose)
        return False
    logmsg("Opening %s" % infile)
    if ida_args:
        cmd = [ida_executable] + ida_args + [idbfile]
    else:
        cmd = [ida_executable, idbfile]
    if verbose:
        logmsg("%s" % " ".join(cmd))
    shell=True
    if os.name == "posix":
        shell=False
    if not list_only:
        subprocess.Popen(cmd, shell)
    # We don't want to wait that it gets closed since it will be a manual
    # operation from the user anyway
    return True

# Re-open an existing IDB and execute an IDA Python script before leaving
# Returns False if does not do anything, the subprocess if it was created
# of True if it was listing only.
def exec_ida_python_script(ida_executable, infile, logfile, idbfile, verbose, ida_args=None, script=None, list_only=False):
    if not script:
        logmsg("Skipping because no script provided. Need a script to execute it in IDA", debug=verbose)
        return False
    if not os.path.isfile(idbfile):
        logmsg("Skipping no existing IDB %s. Execute --analyse first." % idbfile, debug=verbose)
        return False
    if os.path.isfile(infile + ".id0"):
        logmsg("Skipping existing id0 %s. Close IDB first." % (infile + ".id0"), debug=verbose)
        return False
    # If we pass a relative script path from the command line, we try to guess the right path
    # by either looking at the relative path from where idahunt.py is called or by looking at
    # a relative path to the file we analyse is, i.e. where the .idb is
    if not os.path.isabs(script):
        logmsg("WARN: Trying to guess script relative path...")
        abs_script = os.path.abspath(script)
        if not os.path.exists(abs_script):
            logmsg("WARN: Script %s does not exist" % abs_script)
            abs_script = os.path.join(os.path.dirname(infile), script)
            if not os.path.exists(abs_script):
                logmsg("ERROR: Script %s does not exist" % abs_script)
                return False
    else:
        abs_script = script
    logmsg("Executing script %s for %s" % (abs_script, infile))
    # open IDA but at least does not display message boxes to the user.
    if ida_args:
        cmd = [ida_executable, "-A", "-S%s" % abs_script, "-L%s" % logfile] + ida_args + [idbfile]
    else:
        cmd = [ida_executable, "-A", "-S%s" % abs_script, "-L%s" % logfile, idbfile]
    if verbose:
        logmsg("%s" % " ".join(cmd))
    shell=True
    if os.name == "posix":
        shell=False
    # We pass 1 to the script so it can detect (if it wants) to Exit() the IDA
    # session upon completion. 1 is arbitrary. Just needs to be non-zero args
    d = dict(os.environ)
    d["DO_EXIT"] = "1"
    if not list_only:
        return subprocess.Popen(cmd, shell, env=d)
    else:
        return True

# Useful if IDB failed to close correctly. Do not use if IDA Pro is still opened!
def delete_temporary_files(inputdir, list_only=False):
    for f in iglob_hidden("%s/**" % inputdir, recursive=True):
        if f.endswith(".id0") or f.endswith(".id1") or f.endswith(".id2") or \
           f.endswith(".nam") or f.endswith(".til") or f.endswith(".dmp"):
            logmsg("Deleting %s" % f)
            if not list_only:
                os.remove(f)

def delete_asm_files(inputdir, list_only=False):
    for f in iglob_hidden("%s/**" % inputdir, recursive=True):
        if f.endswith(".asm"):
            logmsg("Deleting %s" % f)
            if not list_only:
                os.remove(f)

# main function handling an input folder
# do_file is one of {analyse_file,open_file,exec_ida_python_script}
def do_dir(inputdir, filter, verbose, max_ida, do_file, ida_args=None, script=None, list_only=False):
    pids = []
    call_count = 0
    exec_count = 0
    for f in iglob_hidden("%s/**" % inputdir, recursive=True):
        if os.path.isdir(f):
            continue
        if f.endswith(".idb") or f.endswith(".i64") or \
           f.endswith(".log") or f.endswith(".asm") or \
           f.endswith(".til") or f.endswith(".id0") or \
           f.endswith(".id1") or f.endswith(".id2") or \
           f.endswith(".nam"):
            continue
        f_noext = os.path.splitext(f)[0]
        if filter:
            module_name = filter.split()[0]
            if module_name.endswith(".py"):
                module_name = module_name[:-3]
            module_name = path_to_module_string(module_name)
            m = __import__(module_name, fromlist=[''])
            res = m.main(f, filter)
            if res == None:
                continue
            infile, arch = res

            if arch == "auto":
                arch = detect_arch(f)
                if arch == None:
                    continue
            if arch == 32:
                ida_executable = IDA32
                idbfile = f_noext + ".idb"
            elif arch == 64:
                ida_executable = IDA64
                idbfile = f_noext + ".i64"
            else:
                logmsg("Invalid architecture returned by filter")
                sys.exit()
        else:
                logmsg("Must specify filter")
                sys.exit()

        logfile = f_noext + ".log"
        pid = do_file(ida_executable, f, logfile, idbfile, verbose, ida_args=ida_args, script=script, list_only=list_only)
        # we check if pid is a real PID or if it returned True (list only)
        if pid != False:
            call_count += 1
        if type(pid) != bool:
            exec_count += 1
            pids.append((pid, f))
        if type(pid) == bool:
            continue
        if max_ida == None or len(pids) < max_ida:
            continue

        # Wait for all the IDA instances to complete
        while (len(pids) != 0):
            for p in pids:
                if p[0].poll() != None:
                    pids.remove(p)
                    if os.path.isfile(p[1] + ".id0"):
                        logmsg("ERROR running %s on %s" % (script, p[1]), debug=True)

            logmsg("Waiting on %d IDA instances" % len(pids), end='\r')
            sys.stdout.flush()
            time.sleep(2)
        logmsg("\nContinuing")

    # Wait for all remaining IDA instances to complete
    while (len(pids) != 0):
        for p in pids:
            if p[0].poll() != None:
                pids.remove(p)
                if os.path.isfile(p[1] + ".id0"):
                    logmsg("ERROR running %s on %s" % (script, p[1]), debug=True)

        logmsg("Waiting on remaining %d IDA instances" % len(pids), end='\r')
        sys.stdout.flush()
        time.sleep(5)
    if call_count == 0:
        logmsg("WARN: Didn't find any files to run script on")
    else:
        logmsg("Executed IDA %d/%d times" % (exec_count, call_count))

# https://arcpy.wordpress.com/2012/04/20/146/
def hms_string(sec_elapsed):
    h = int(sec_elapsed / (60 * 60))
    m = int((sec_elapsed % (60 * 60)) / 60)
    s = sec_elapsed % 60.
    return "{}:{:>02}:{:>05.2f}".format(h, m, s)

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('--inputdir', dest='inputdir', default=None,
                        help='Input folder to search for files')
    parser.add_argument('--analyse', '--analyze', dest='analyse', default=False,
                        action='store_true', help='analyse all files \
                        i.e. create .idb for all of them')
    parser.add_argument('--open', dest='open', default=False, action='store_true',
                        help='open all files into IDA (debug only)')
    parser.add_argument('--ida-args', dest='ida_args', default=None,
                        help='Additional arguments to pass to IDA (e.g. -p<processor> -i<entry_point> -b<load_addr>)')
    parser.add_argument('--scripts', dest='scripts', nargs="+", default=None,
                        help='List of IDA Python scripts to execute in this order')
    parser.add_argument('--filter', dest='filter', default="filters/default.py",
                        help='External python script with optional arguments \
                        defining a filter for the names of the files to \
                        analyse. See filters/names.py for example')
    parser.add_argument('--cleanup', dest='cleanup', default=False,
                        action='store_true', help='Cleanup i.e. remove .asm \
                        files that we don\'t need')
    parser.add_argument('--temp-cleanup', dest='cleanup_temporary',
                        default=False, action='store_true', help='Cleanup \
                        temporary database files i.e. remove .id0, .id1, .id2, \
                        .nam, .dmp files if IDA Pro crashed and did not delete them')
    parser.add_argument('--verbose', dest='verbose', default=False, action='store_true',
                        help='be more verbose to debug script')
    parser.add_argument('--max-ida', dest='max_ida', default=10, type=int,
                        help='Maximum number of instances of IDA to run at a time (default: 10)')
    parser.add_argument('--list-only', dest='list_only', default=False, action="store_true",
                        help='List only what files would be handled without executing IDA')
    parser.add_argument('--version', dest='ida_version', default="7.6",
                        help='Override IDA version (e.g. "7.6"). This is used to find the path \
                        of IDA on Windows.')
    args = parser.parse_args()

    if not args.analyse and not args.cleanup_temporary and \
        not args.cleanup and args.scripts == None and args.open == None:
        logmsg("ERROR: You didn't specify an action. Don't know what to do")
        logmsg("ERROR: Try --analyse or --cleanup or --temp-cleanup or --scripts or --open")
        sys.exit(1)

    if args.list_only:
        logmsg("Simulating only...")

    ida_version = args.ida_version
    ida32_found = False
    try:
        IDA32 = os.environ["IDA32"]
        ida32_found = True
    except:
        if os.name == "posix":
            try:
                IDA32 = subprocess.check_output("which idaq", shell=True).rstrip(b'\n').decode('utf-8')
                ida32_found = True
            except subprocess.CalledProcessError:
                pass
            if not ida32_found:
                try:
                    # IDA 7 switched binary names
                    IDA32 = subprocess.check_output("which ida", shell=True).rstrip(b'\n').decode('utf-8')
                    ida32_found = True
                except subprocess.CalledProcessError:
                    pass
        else:
            #IDA32="C:\\Program Files (x86)\\IDA 6.95\\idaq.exe"
            #IDA32="C:\\Program Files\\IDA " + ida_version + "\\ida.exe"
            IDA32="C:\\Program Files\\IDA Pro " + ida_version + "\\ida.exe"
            # XXX - Test the file exists here... We shouldn't rely on a version
            ida32_found = True

    ida64_found = False
    try:
        IDA64 = os.environ["IDA64"]
        ida64_found = True
    except:
        if os.name == "posix":
            try:
                IDA64 = subprocess.check_output("which idaq64", shell=True).rstrip(b'\n').decode('utf-8')
                ida64_found = True
            except subprocess.CalledProcessError:
                pass
            if not ida64_found:
                try:
                    # IDA 7 switched binary names
                    IDA64 = subprocess.check_output("which ida64", shell=True).rstrip(b'\n').decode('utf-8')
                    ida64_found = True
                except subprocess.CalledProcessError:
                    pass
        else:
            #IDA64="C:\\Program Files (x86)\\IDA 6.95\\idaq64.exe"
            #IDA64="C:\\Program Files\\IDA " + ida_version + "\\ida64.exe"
            IDA64="C:\\Program Files\\IDA Pro " + ida_version + "\\ida64.exe"
            # XXX - Test the file exists here... We shouldn't rely on a version
            ida64_found = True

    if not ida32_found or not ida64_found:
        logmsg("You don't seem to have 32-bit and 64-bit ida installed? If you do specify the \
                path in IDA32 and IDA64 environment variables, since we can't find them.")
        sys.exit(1)

    if args.verbose:
        logmsg("IDA32 = %s" % IDA32)
        logmsg("IDA64 = %s" % IDA64)

    if not args.inputdir:
        logmsg("ERROR: You need to provide an input directory with --inputdir")
        sys.exit()

    if not os.path.exists(args.inputdir):
        logmsg("ERROR: The path you provided doesn't exist: %s" % args.inputdir)
        sys.exit()

    # NOTE: The order here is important. We do it this way so that you could do
    # clean the dir, create idbs, rename all the idbs, and then update a
    # database all in one run

    if args.list_only and (not args.analyse and not args.scripts and not args.cleanup and not args.cleanup_temporary and args.open == None):
        logmsg("ERROR: You must use --cleanup, --analyse or --scripts with --list-only")
        sys.exit()

    start_time = time.time()

    ida_args = None
    if args.ida_args:
        # lstrip() to allow having a space as first character (to avoid Python to parse our
        # IDA arguments)
        ida_args = args.ida_args.lstrip().split()

    if args.cleanup_temporary:
        logmsg("CLEANUP TEMP FILES")
        delete_temporary_files(args.inputdir, list_only=args.list_only)
    if args.cleanup:
        logmsg("CLEANUP ASM FILES")
        delete_asm_files(args.inputdir, list_only=args.list_only)

    if args.analyse:
        logmsg("ANALYSING FILES")
        do_dir(args.inputdir, args.filter, args.verbose, max_ida=args.max_ida,
               do_file=analyse_file, list_only=args.list_only, ida_args=ida_args)

    if args.scripts:
        logmsg("EXECUTE SCRIPTS")
        scripts = []
        for s in args.scripts:
            if not os.path.isabs(s):
                # Note: we will try to guess its relative path later in exec_ida_python_script()
                logmsg("WARN: %s to be executed in IDA Pro, is not an absolute path" % s)
            scripts.append(s)

        for script in scripts:
            do_dir(args.inputdir, args.filter, args.verbose, max_ida=args.max_ida,
                   do_file=exec_ida_python_script, script=script, list_only=args.list_only,
                   ida_args=ida_args)

    if args.open:
        logmsg("OPENING FILES")
        do_dir(args.inputdir, args.filter, args.verbose, max_ida=args.max_ida,
               do_file=open_file, list_only=args.list_only, ida_args=ida_args)
        sys.exit()

    end_time = time.time()
    logmsg("Took {} to execute this".format(hms_string(end_time - start_time)))
