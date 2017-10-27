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
# Tested under windows and linux.
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

def path_to_module_string(p):
    return p.replace("/", ".").replace("\\", ".")

# Does the initial auto-analysis when we first open a file in IDA
def analyse_file(ida_executable, infile, logfile, idbfile, verbose, script=None, list_only=False):
    if os.path.isfile(idbfile):
        logmsg("Skipping existing IDB %s. Analysis has already been made" % idbfile, debug=verbose)
        return None
    if os.path.isfile(infile + ".id0"):
        logmsg("Skipping existing id0 %s. Close IDB first." % (infile + ".id0"), debug=verbose)
        return None
    logmsg("Analysing %s" % infile)
    cmd = [ida_executable, "-B", "-L%s"% logfile, infile]
    if verbose:
        logmsg("%s" % " ".join(cmd))
    shell=True
    if os.name == "posix":
        shell=False

    if not list_only:
        return subprocess.Popen(cmd, shell)
    else:
        return None

# Re-open an existing IDB
def open_file(ida_executable, infile, logfile, idbfile, verbose, script=None, list_only=False):
    if not os.path.isfile(idbfile):
        logmsg("Skipping no existing IDB %s. Execute --analyse first." % idbfile, debug=verbose)
        return None
    if os.path.isfile(infile + ".id0"):
        logmsg("Skipping existing id0 %s. Close IDB first." % (infile + ".id0"), debug=verbose)
        return None
    logmsg("Opening %s" % infile)
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
    return None

# Re-open an existing IDB and execute an IDA Python script before leaving
def exec_ida_python_script(ida_executable, infile, logfile, idbfile, verbose, script=None, list_only=False):
    if not script:
        logmsg("Skipping because no script provided. Need a script to execute it in IDA", debug=verbose)
        return None
    if not os.path.isfile(idbfile):
        logmsg("Skipping no existing IDB %s. Execute --analyse first." % idbfile, debug=verbose)
        return None
    if os.path.isfile(infile + ".id0"):
        logmsg("Skipping existing id0 %s. Close IDB first." % (infile + ".id0"), debug=verbose)
        return None
    logmsg("Executing script %s for %s" % (script, infile))
    # open IDA but at least does not display message boxes to the user.
    cmd = [ida_executable, "-A", "-S%s" % script, "-L%s" % logfile, idbfile]
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
        return None

# Useful if IDB failed to close correctly. Do not use if IDA Pro is still opened!
def delete_temporary_files(inputdir, list_only=False):
    for f in glob.iglob("%s/**" % inputdir, recursive=True):
        if f.endswith(".id0") or f.endswith(".id1") or f.endswith(".id2") or \
           f.endswith(".nam") or f.endswith(".til") or f.endswith(".dmp"):
            logmsg("Deleting %s" % f)
            if not list_only:
                os.remove(f)

def delete_asm_files(inputdir, list_only=False):
    for f in glob.iglob("%s/**" % inputdir, recursive=True):
        if f.endswith(".asm"):
            logmsg("Deleting %s" % f)
            if not list_only:
                os.remove(f)

# main function handling an input folder
# analyse_file is one of {analyse_file,open_file,exec_ida_python_script}
def do_dir(inputdir, filter, verbose, max_ida, do_file, script=None, list_only=False):
    pids = []
    call_count = 0
    for f in glob.iglob("%s/**" % inputdir, recursive=True):
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
        pid = do_file(ida_executable, f, logfile, idbfile, verbose, script=script, list_only=list_only)
        call_count += 1
        if pid != None:
            pids.append((pid, f))
        if pid == None:
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
        print("") # XXX - Why?

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('--inputdir', dest='inputdir', default=None,
                        help='Input folder to search for files')
    parser.add_argument('--analyse', '--analyze', dest='analyse', default=False,
                        action='store_true', help='analyse all files \
                        i.e. create .idb for all of them')
    parser.add_argument('--open', dest='open', default=False, action='store_true',
                        help='open all files into IDA (debug only)')
    parser.add_argument('--scripts', dest='scripts', nargs="+",
                        help='List of IDA Python scripts to execute in this order')
    parser.add_argument('--filter', dest='filter', default=None,
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
    parser.add_argument('--max-ida', dest='max_ida', default=10,
                        help='Maximum number of instances of IDA to run at a time (default: 10)')
    parser.add_argument('--list-only', dest='list_only', default=False, action="store_true",
                        help='List only what files would be handled without executing IDA')
    args = parser.parse_args()

    if args.list_only:
        logmsg("Simulating only...")

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
            IDA32="C:\\Program Files (x86)\\IDA 6.95\\idaq.exe"
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
            IDA64="C:\\Program Files (x86)\\IDA 6.95\\idaq64.exe"
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
        logmsg("You need to provide an input directory with --inputdir")
        sys.exit()

    # NOTE: The order here is important. We do it this way so that you could do
    # clean the dir, create idbs, rename all the idbs, and then update a
    # database all in one run

    if args.list_only and (not args.analyse and not args.scripts):
        logmsg("ERROR: You must use --analyse or --scripts with --list-only")
        sys.exit()

    if args.cleanup_temporary:
        delete_temporary_files(args.inputdir)
    if args.cleanup:
        delete_asm_files(args.inputdir)

    if args.analyse:
        logmsg("ANALYSING FILES")
        do_dir(args.inputdir, args.filter, args.verbose, max_ida=args.max_ida,
               do_file=analyse_file, list_only=args.list_only)

    if args.scripts:
        logmsg("EXECUTE SCRIPTS")
        scripts = []
        for s in args.scripts:
            if not os.path.isabs(s):
                logmsg("WARN: You didn't provide an absolute path for the scripts as it will be executed in IDA Pro")
                logmsg("WARN: Using %s" % os.path.abspath(s))
            scripts.append(os.path.abspath(s))

        for script in scripts:
            do_dir(args.inputdir, args.filter, args.verbose, max_ida=args.max_ida,
                   do_file=exec_ida_python_script, script=script, list_only=args.list_only)

    if args.open:
        logmsg("OPENING FILES")
        do_dir(args.inputdir, args.filter, args.verbose, max_ida=None,
               do_file=open_file, list_only=args.list_only)
        sys.exit()
