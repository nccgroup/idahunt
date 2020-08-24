#!/usr/bin/python3
#
# This file is part of idahunt.
# Copyright (c) 2017, Aaron Adams <aaron.adams(at)nccgroup(dot)trust>
# Copyright (c) 2017, Cedric Halbronn <cedric.halbronn(at)nccgroup(dot)trust>
#
# Filter for arbitrary names to be used by idahunt.py command line:
# e.g. idahunt.py --filter "filters/names.py -n Download -e exe -a 32"
#      idahunt.py --filter "filters/names.py -l 64"

import argparse
import os
import re
import sys
import subprocess
import time

def logmsg(s, end=None, debug=True):
    if not debug:
        return
    if type(s) == str:
        if end != None:
            print("[names] " + s),
        else:
            print("[names] " + s)
    else:
        print(s)

# do we actually treat it?
def filter(f, name, extension, arch, length, verbose=True):
    if name and not name in os.path.basename(f):
        logmsg("Skipping non-matching name %s in %s" % (name, os.path.basename(f)))
        return None
    filename, file_extension = os.path.splitext(f)
    if extension and not extension.startswith("."):
        extension = "." + extension
    if extension and file_extension != extension:
        logmsg("Skipping non-matching extension %s in %s" % (extension, os.path.basename(f)))
        return None
    if name and not name in os.path.basename(f):
        logmsg("Skipping non-matching name %s in %s" % (name, os.path.basename(f)))
        return None
    if length and len(os.path.basename(f)) != length:
        logmsg("Skipping non-matching name: len(%s) != %d" % (os.path.basename(f), length))
        return None

    if arch == "64":
        arch_ = 64
    elif arch == "32":
        arch_ = 32
    elif arch == "auto":
        arch_ = "auto"
    else:
        logmsg("Unknown architecture: %s. You need to specify it with -a" % arch)
        return None

    return f, arch_

def main(f, cmdline):
    # We override sys.argv so argparse can parse our arguments :)
    sys.argv = cmdline.split()

    parser = argparse.ArgumentParser(prog=cmdline)
    parser.add_argument('-n', dest='name', default=None, help='pattern \
                        to include in the name')
    parser.add_argument('-e', dest='extension', default=None, help='Exact \
                        extension to match')
    parser.add_argument('-a', dest='arch', default=None, help='Assume \
                         architecture known by user')
    parser.add_argument('-l', dest='length', default=None, type=int, help='Name length \
                         to include (e.g. 64 for a SHA256 since it is 32 bytes stored in hex digits)')
    parser.add_argument('-v', dest='verbose', default=False, action='store_true'
                        , help='be more verbose to debug script')
    args = parser.parse_args()

    return filter(f, args.name, args.extension, args.arch, args.length, args.verbose)
