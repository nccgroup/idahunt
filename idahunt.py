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
from pathlib import Path
import sqlite3

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

# https://arcpy.wordpress.com/2012/04/20/146/
def hms_string(sec_elapsed):
    h = int(sec_elapsed / (60 * 60))
    m = int((sec_elapsed % (60 * 60)) / 60)
    s = sec_elapsed % 60.
    return "{}:{:>02}:{:>05.2f}".format(h, m, s)

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
        logmsg("%s: not an EXE or ELF file. Ignoring automatic architecture detection" % filename)

    return arch

# Does the initial auto-analysis when we first open a file in IDA
# Returns False if does not do anything, the subprocess if it was created
# of True if it was listing only.
def analyse_file(ida_executable, infile, logfile, idbfile, verbose, ida_args=None, script=None, list_only=False, env=None):
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
def open_file(ida_executable, infile, logfile, idbfile, verbose, ida_args=None, script=None, list_only=False, env=None):
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
def exec_ida_python_script(ida_executable, infile, logfile, idbfile, verbose, ida_args=None, script=None, list_only=False, env=None):
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
    if env is not None:
        if verbose:
            logmsg("Environment variables:")
            for (k,v) in env.items():
                logmsg("%s=%s" % (k, v))
        d.update(env)
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

def check_diff_export_done(f, verbose):
    f_noext = os.path.splitext(f)[0]
    sqlitefile = f_noext + ".sqlite"
    sqlitecrashfile = f_noext + ".sqlite-crash"
    if os.path.isfile(sqlitefile) and not os.path.isfile(sqlitecrashfile):
        logmsg("Skipping existing sqlite %s. Diff-export has already been made" % sqlitefile, debug=verbose)
        return True
    return False

# main function handling an input folder
# - "do_file" is one of {analyse_file,open_file,exec_ida_python_script}
# - "do_check" is one of {check_diff_export_done}
def do_dir(inputdir, filter, verbose, max_ida, do_file, ida_args=None, script=None, list_only=False, env=None, do_check=None):
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
           f.endswith(".nam") or f.endswith(".sqlite"):
            continue
        if do_check is not None and do_check(f, verbose):
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
        env_current = None
        if env is not None:
            env_current = dict(env)
            for (k,v) in env_current.items():
                env_current[k] = v.replace("%%FILE%%", os.path.basename(f_noext))
        pid = do_file(ida_executable, f, logfile, idbfile, verbose, ida_args=ida_args, script=script, list_only=list_only, env=env_current)
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

def parse_diff_results(db_path):
    txt_path = db_path.parent / (str(db_path.stem) + ".txt")
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()
    rows = cursor.execute("SELECT * from RESULTS WHERE type != \"best\"")
    s = ""
    for row in rows:
        type_, line, address, name, address2, name2, ratio, bb1, bb2, description = row
        if type_ == "best":
            continue
        max_ratio = 1.0
        if float(ratio) >= max_ratio:
            continue
        s += "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" % (type_, line, address, name, address2, name2, ratio, bb1, bb2, description)
    txt_path.write_text(s)

# compare 2 sqlite database with diaphora and generate the diff sqlite
def diff_all(inputdir, filename, verbose, max_python, diaphora_path, list_only=False):
    pids = []
    call_count = 0
    exec_count = 0
    files_list = []
    for f in iglob_hidden("%s/**/%s" % (inputdir, filename), recursive=True):
        if os.path.isdir(f):
            continue
        files_list.append(f)

    for i in range(len(files_list)-1):
        f = Path(files_list[i])
        f2 = Path(files_list[i+1])
        # We assume files are in a parent folder that dictate the version
        # and that the versions are in alphabetical order so we can diff 2 consecutive ones
        version = f.parent.name
        version2 = f2.parent.name

        # We save the diff database in the most recent file folder
        outputdir = f2.parent/f"{version}_vs_{version2}"
        diaphoradb_path = outputdir / f"{filename}.diaphora"
        diaphoratxt_path = outputdir / f"{filename}.txt"

        if os.path.isfile(diaphoradb_path) and os.path.isfile(diaphoratxt_path):
            logmsg("Skipping existing diff %s vs %s as was already been made" % (version, version2), debug=verbose)
            continue

        # The diff database is created at the end when the results have been computed so safe
        if os.path.isfile(diaphoradb_path):
            logmsg("Skipping existing diff sqlite %s creation" % diaphoradb_path, debug=verbose)
            parse_diff_results(diaphoradb_path)
            continue
        outputdir.mkdir(parents=True, exist_ok=True)

        f_noext = os.path.splitext(f)[0]
        f2_noext = os.path.splitext(f2)[0]

        sqlitefile = f_noext + ".sqlite"
        sqlitefile2 = f2_noext + ".sqlite"

        logmsg("Diffing %s vs %s" % (version, version2))
        python_path = sys.executable
        script_path = os.path.join(diaphora_path, "diaphora.py")
        cmd = [python_path, script_path, sqlitefile, sqlitefile2, "-o", str(diaphoradb_path)]
        if verbose:
            logmsg("%s" % " ".join(cmd))
        if list_only:
            pid = True
        else:
            shell=True
            if os.name == "posix":
                shell=False
            # XXX - hide stdout output from the command and save it into a .log file
            pid = subprocess.Popen(cmd, shell)

        # we check if pid is a real PID or if it returned True (list only)
        call_count += 1
        if type(pid) != bool:
            exec_count += 1
            pids.append((pid, version, version2, diaphoradb_path))
        if type(pid) == bool:
            continue
        if max_python == None or len(pids) < max_python:
            continue

        # Wait for all the Python instances to complete
        while (len(pids) != 0):
            for p in pids:
                if p[0].poll() != None:
                    pids.remove(p)
                    if not os.path.isfile(p[3]):
                        logmsg("ERROR diffing %s vs %s" % (p[1], p[2]), debug=True)
                    parse_diff_results(p[3])

            logmsg("Waiting on %d Python instances" % len(pids), end='\r')
            sys.stdout.flush()
            time.sleep(2)
        logmsg("\nContinuing")

    # Wait for all remaining Python instances to complete
    while (len(pids) != 0):
        for p in pids:
            if p[0].poll() != None:
                pids.remove(p)
                if not os.path.isfile(p[3]):
                    logmsg("ERROR diffing %s vs %s" % (p[1], p[2]), debug=True)
                parse_diff_results(p[3])

        logmsg("Waiting on remaining %d Python instances" % len(pids), end='\r')
        sys.stdout.flush()
        time.sleep(5)
    if call_count == 0:
        logmsg("WARN: Didn't find any files to run diff on")
    else:
        logmsg("Executed Python %d/%d times" % (exec_count, call_count))

# A filename can't contain any of the following characters: \ / : * ? " < > |
# XXX - We could potentially use a demangling library like https://golang.org/pkg/cmd/vendor/github.com/ianlancetaylor/demangle/ ?
def replace_bad_characters(funcname):
    funcname = funcname.replace(":", "-")
    funcname = funcname.replace("?", "")
    funcname = funcname.replace("*", "")
    funcname = funcname.replace("<", "-")
    funcname = funcname.replace(">", "-")
    return funcname

# generate HTML for one given function among all the versions of a given file by using previously computed diff information
def show_all(inputdir, filter, filename, funcname, verbose, max_ida, diaphora_path, list_only=False):
    pids = []
    call_count = 0
    exec_count = 0
    files_list = []
    for f in iglob_hidden("%s/**/%s" % (inputdir, filename), recursive=True):
        if os.path.isdir(f):
            continue
        files_list.append(f)

    for i in range(len(files_list)-1):
        f = Path(files_list[i])
        f2 = Path(files_list[i+1])
        # We assume files are in a parent folder that dictate the version
        # and that the versions are in alphabetical order so we can diff 2 consecutive ones
        version = f.parent.name
        version2 = f2.parent.name

        sqlitedb_path = f.parent / (f.stem + ".sqlite")
        sqlitedb2_path = f2.parent / (f2.stem + ".sqlite")
        outputdir = f2.parent/f"{version}_vs_{version2}"
        diaphoradb_path = outputdir / f"{filename}.diaphora"
        diaphoratxt_path = outputdir / f"{filename}.txt"
        print(sqlitedb_path, sqlitedb2_path)

        if not os.path.isfile(sqlitedb_path) or not os.path.isfile(sqlitedb2_path) or not os.path.isfile(diaphoradb_path) or not os.path.isfile(diaphoratxt_path):
            logmsg("Skipping existing show %s vs %s as diff not made yet" % (version, version2), debug=verbose)
            continue

        output_html_dir = outputdir / filename
        html_asm_path = output_html_dir / f"{replace_bad_characters(funcname)}_asm.html"
        html_pseudo_path = output_html_dir / f"{replace_bad_characters(funcname)}_pseudo.html"

        print(html_asm_path, html_pseudo_path)

        if os.path.isfile(html_asm_path) and os.path.isfile(html_pseudo_path):
            logmsg("Skipping existing show %s vs %s for %s" % (version, version2, funcname), debug=verbose)
            continue
        output_html_dir.mkdir(parents=True, exist_ok=True)

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

        name, address, address2 = None, None, None
        connection = sqlite3.connect(diaphoradb_path)
        cursor = connection.cursor()
        rows = cursor.execute(f"SELECT name, address, address2 from RESULTS WHERE type != \"best\" and name = \"{funcname}\"")
        for row in rows:
            name, address, address2 = row
            break

        if not name or not address or not address2:
            logmsg("Skipping show %s vs %s for %s due to invalid sqlite response. Check function name?" % (version, version2, funcname), debug=verbose)
            continue

        env = {
            "DIAPHORA_AUTO_HTML":"1",
            "DIAPHORA_DB1":str(sqlitedb_path),
            "DIAPHORA_DB2":str(sqlitedb2_path),
            "DIAPHORA_DIFF":str(diaphoradb_path),
            "DIAPHORA_EA1":address,
            "DIAPHORA_EA2":address2,
            "DIAPHORA_HTML_ASM":str(html_asm_path),
            "DIAPHORA_HTML_PSEUDO":str(html_pseudo_path),
        }

        logmsg("Showing %s vs %s for %s" % (version, version2, funcname))
        script = os.path.join(diaphora_path, "diaphora_ida.py")
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
        if verbose:
            logmsg("Environment variables:")
            for (k,v) in env.items():
                logmsg("%s=%s" % (k, v))
        d.update(env)
        if list_only:
            pid = True
        else:
            pid = subprocess.Popen(cmd, shell, env=d)

        # we check if pid is a real PID or if it returned True (list only)
        call_count += 1
        if type(pid) != bool:
            exec_count += 1
            pids.append((pid, version, version2, html_asm_path, html_pseudo_path))
        if type(pid) == bool:
            continue
        if max_ida == None or len(pids) < max_ida:
            continue

        # Wait for all the IDA instances to complete
        while (len(pids) != 0):
            for p in pids:
                if p[0].poll() != None:
                    pids.remove(p)
                    if not os.path.isfile(p[3]) or not os.path.isfile(p[4]):
                        logmsg("ERROR showing %s vs %s" % (p[1], p[2]), debug=True)

            logmsg("Waiting on %d IDA instances" % len(pids), end='\r')
            sys.stdout.flush()
            time.sleep(2)
        logmsg("\nContinuing")

    # Wait for all remaining IDA instances to complete
    while (len(pids) != 0):
        for p in pids:
            if p[0].poll() != None:
                pids.remove(p)
                if not os.path.isfile(p[3]) or not os.path.isfile(p[4]):
                    logmsg("ERROR showing %s vs %s" % (p[1], p[2]), debug=True)

        logmsg("Waiting on remaining %d IDA instances" % len(pids), end='\r')
        sys.stdout.flush()
        time.sleep(5)
    if call_count == 0:
        logmsg("WARN: Didn't find any files to run diff on")
    else:
        logmsg("Executed IDA %d/%d times" % (exec_count, call_count))

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('--inputdir', dest='inputdir', default=None,
                        help='Input folder to search for files')
    parser.add_argument('--analyse', dest='analyse', default=False,
                        action='store_true', help='analyse all files \
                        i.e. create .idb for all of them')
    parser.add_argument('--open', dest='open', default=False, action='store_true',
                        help='open all files into IDA (debug only)')
    parser.add_argument('--ida-args', dest='ida_args', default=None,
                        help='Additional arguments to pass to IDA (e.g. -p<processor> -i<entry_point> -b<load_addr>)')
    parser.add_argument('--scripts', dest='scripts', nargs="+", default=None,
                        help='List of IDA Python scripts to execute in this order')
    parser.add_argument('--diff', dest='diff', default=False,
                        action='store_true', help='Diff all files with diaphora')
    parser.add_argument('--html', dest='html', default=False,
                        action='store_true', help='Generate HTML diff (asm + pseudocode) for all files with diaphora')
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
    parser.add_argument('--version', dest='ida_version', default="8.1",
                        help='Override IDA version (e.g. "8.1"). This is used to find the path \
                        of IDA on Windows.')
    parser.add_argument('--diaphora-path', dest='diaphora_path', default=None,
                        help='Specify diaphora path when --diff is used. This is used to find the diaphora_ida.py and diaphora.py scripts')
    parser.add_argument('--filename', dest='filename', default=None,
                        help='Specify filename to handle when --diff or --html is used. Indeed, we are required to diff files with the same name but from different folders')
    parser.add_argument('--funcname', dest='funcname', default=None,
                        help='Specify function name when --html is used. The function name is from first database to generate the asm/pseudocode diff for')
    args = parser.parse_args()

    if not args.analyse and not args.cleanup_temporary and \
        not args.cleanup and args.scripts is None and not args.open and not args.diff and not args.html:
        logmsg("ERROR: You didn't specify an action. Don't know what to do")
        logmsg("ERROR: Try --analyse or --cleanup or --temp-cleanup or --scripts or --open or --diff or --html")
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
            #IDA32="C:\\Program Files\\IDA Pro " + ida_version + "\\ida.exe"
            IDA32="C:\Program Files\IDA Core " + ida_version + "\\ida.exe"
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
            #IDA64="C:\\Program Files\\IDA Pro " + ida_version + "\\ida64.exe"
            IDA64="C:\Program Files\IDA Core " + ida_version + "\\ida64.exe"
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

    if args.list_only and (not args.analyse and not args.scripts and not args.cleanup and not args.cleanup_temporary and not args.open and not args.diff and not args.html):
        logmsg("ERROR: You must use --cleanup, --analyse, --temp-cleanup, --open, --diff, --html or --scripts with --list-only")
        sys.exit(1)
    
    if args.diff:
        if args.analyse or args.scripts or args.open or args.ida_args is not None:
            logmsg("ERROR: Diffing only supports running without other actions or additional ida arguments")
            sys.exit(1)
        if args.filename is None:
            logmsg("ERROR: Diffing requires a filename to diff with --diff-name")
            sys.exit(1)
        if args.diaphora_path is None:
            logmsg("ERROR: Diffing requires a path to diaphora root folder")
            sys.exit(1)
        if not os.path.exists(os.path.join(args.diaphora_path, "diaphora.py")):
            logmsg("ERROR: Wrong diaphora path")
            sys.exit(1)

    if args.html:
        if args.funcname is None:
            logmsg("ERROR: Generating asm/pseudocode requires a function name to generate HTML for with --funcname")
            sys.exit(1)

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

    if args.diff:
        logmsg("EXECUTE DIFF-EXPORT")
        script = os.path.join(args.diaphora_path, "diaphora_ida.py")
        env = {
            "DIAPHORA_AUTO": "1",
            "DIAPHORA_USE_DECOMPILER": "1",
            "DIAPHORA_EXPORT_FILE": "%%FILE%%.sqlite",
        }
        filter_ = f"filters\\diff.py -n {args.filename}"
        do_dir(args.inputdir, filter_, args.verbose, max_ida=args.max_ida,
               do_file=exec_ida_python_script, script=script, list_only=args.list_only,
               ida_args=None, env=env, do_check=check_diff_export_done)

        # XXX - use same max python instances as IDA instances
        logmsg("EXECUTE DIFF")
        diff_all(args.inputdir, args.filename, args.verbose, args.max_ida, args.diaphora_path, list_only=args.list_only)

    if args.html:
        logmsg("EXECUTE GENERATE HTML")
        filter_ = f"filters\\diff.py -n {args.filename}"
        show_all(args.inputdir, filter_, args.filename, args.funcname, args.verbose, args.max_ida, args.diaphora_path, list_only=args.list_only)

    if args.diff or args.html:
        end_time = time.time()
        logmsg("Took {} to execute this".format(hms_string(end_time - start_time)))
        sys.exit(0)

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
        end_time = time.time()
        logmsg("Took {} to execute this".format(hms_string(end_time - start_time)))
        sys.exit()

    end_time = time.time()
    logmsg("Took {} to execute this".format(hms_string(end_time - start_time)))
